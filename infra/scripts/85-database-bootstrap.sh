#!/usr/bin/env bash
#  The schema, applied once, by an identity the control plane does not hold.
#
#      ./infra/scripts/85-database-bootstrap.sh
#
#  **This is the only thing in the deployment that performs DDL.**  It runs as
#  ${MIGRATOR_SA_ID}, against the migration DSN, and it is the reason the
#  runtime role can be granted no CREATE at all.  The hero job never migrates:
#  it reads the migration ledger and refuses to start if the ledger is absent or
#  disagrees with the build, which is a property worth having only because the
#  thing that *can* write schema is a separate job under a separate identity
#  with a separate credential.
#
#      bootstrap job -> migrator identity -> apply missing migrations -> exit
#      hero job      -> runtime identity  -> read the ledger -> refuse or work
#
#  Idempotent, and that is the point rather than a convenience: the command it
#  runs applies what is missing and then re-reads the complete ledger to prove
#  it is current.  A second run applies nothing and still proves it.  Re-run it
#  after every image that adds a migration, before 90-hero-job.sh.
#
#  **It also grants the runtime role, in the same run.**  A migration that adds
#  a table does not grant on it, and for one release that step lived in
#  infra/README.md as an instruction to a person.  Migration 7 added
#  sandbox_rail, the block was not re-run, and the deployed control plane could
#  not touch the simulated external system at all -- which the Action Gate
#  recorded, correctly, as EXECUTOR_EXCEPTION and a durable UNCERTAIN row with
#  no redispatch, and which therefore looked like a lifecycle rather than a
#  permission.  So the grant list is data in ``adapters.sql.runtime_grants``,
#  applied here by the only identity that owns these tables, and read back from
#  the live catalogue afterwards.  ${DATABASE_RUNTIME_ROLE} names the role; it
#  is a role name and not a credential, and the runtime's password is not read
#  by this job at all.
#
#      BOOTSTRAP_REPORT_ONLY=1 ./infra/scripts/85-database-bootstrap.sh
#
#  reads those privileges back and changes nothing -- no migration, no grant.
#  It is how the state of a database *before* a repair is established.  What it
#  reads back is the whole vocabulary, not the grant list: for every runtime
#  table it asks about SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES and
#  TRIGGER, so a privilege nobody enumerated is a WRONG line rather than a
#  question that was never put; for every runtime schema, USAGE and CREATE; for
#  every schema and table, whether the role effectively owns it; and once,
#  whether it holds CREATE on the database.  It reports and never revokes --
#  repairing a widening is a decision, not a step in a deploy.
#
#      SANDBOX_EVIDENCE_KEYS=<execution-id>[,<execution-id>...] \
#        ./infra/scripts/85-database-bootstrap.sh
#
#  reads the *simulated external world* for those execution ids, on a read-only
#  connection, and changes nothing either.  It exists because the reconciliation
#  proof rests on a claim about something outside MUSTER -- a synthetic
#  acceptance that committed before the process lost its answer -- and a Gate row
#  saying CONFIRMED after a reconciliation is not evidence of that, since the
#  reconciliation is what wrote it.  It touches ``sandbox_rail`` and nothing
#  else: no case, no transcript, no execution row, no tenant.
#
#      0   the schema is current and the runtime privileges are exactly the set
#      1   they are not, or the job could not establish that they are
#      2   the arguments or the project were not usable, and nothing was deployed
#      4   an execution was created and its outcome could not be read
#
#  Nothing here prints a DSN or a password.  The migration credential is
#  resolved by Cloud Run from a pinned Secret Manager version straight into the
#  container's environment; it does not pass through this script, an env-vars
#  file, or an argument list.  The command it runs reports a failure *class*
#  rather than a driver message, for the same reason.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

#  Fail closed before anything is created.  'latest' is refused here exactly as
#  it is for the signing key: a credential that re-resolves at every cold start
#  is a credential nobody reviewed.
muster::require_pinned_secret_version \
  DATABASE_MIGRATION_DSN_SECRET_VERSION \
  DATABASE_SERVER_CA_SECRET_VERSION

if [[ -z "${HERO_VPC_NETWORK}" || -z "${HERO_VPC_SUBNET}" ]]; then
  cat >&2 <<NETWORK
  The Cloud SQL instance has a private address and no public IPv4, so this job
  reaches it the same way the hero job reaches the agents: out through the
  project's own VPC.  Without --network/--subnet the job has no route to it at
  all, and would fail on connect_timeout rather than on anything diagnostic.

      HERO_VPC_NETWORK  is '${HERO_VPC_NETWORK}'
      HERO_VPC_SUBNET   is '${HERO_VPC_SUBNET}'

NETWORK
  exit 2
fi

muster::banner "database bootstrap ${BOOTSTRAP_JOB}"
echo "  identity  ${MIGRATOR_SA}"
echo "  image     ${CONTROL_PLANE_IMAGE}"
echo "  egress    ${HERO_VPC_EGRESS} via ${HERO_VPC_NETWORK}/${HERO_VPC_SUBNET}"
echo "  runtime   ${DATABASE_RUNTIME_ROLE:-(none: no grant will be applied)}"
echo "  secrets   ${DATABASE_MIGRATION_DSN_SECRET}:${DATABASE_MIGRATION_DSN_SECRET_VERSION} (env)"
echo "            ${DATABASE_SERVER_CA_SECRET}:${DATABASE_SERVER_CA_SECRET_VERSION} (file)"

#  Written to a file by the same emitter every other stage uses, so a value
#  containing the delimiter cannot silently truncate the deployment.
muster::env_file "${BOOTSTRAP_JOB}"
env_file="${MUSTER_ENV_FILE}"
{
  muster::env_entry MUSTER_DATABASE_DEPLOYMENT "CLOUD_SQL"
  #  A role name, never a credential.  Emitted only when one was named, so an
  #  operator who set it empty gets the command's "no runtime grant" line
  #  rather than a grant to a role called "".
  if [[ -n "${DATABASE_RUNTIME_ROLE}" ]]; then
    muster::env_entry MUSTER_RUNTIME_ROLE "${DATABASE_RUNTIME_ROLE}"
  fi
} > "${env_file}"

#  Private Google Access, for the same reason 90-hero-job.sh needs it: with
#  --vpc-egress=all-traffic an instance in this subnet has no external address,
#  and Secret Manager is reached over Google's network like everything else.
muster::require_private_google_access

#  ---- one secret per mounted directory ------------------------------------
#
#  The migration DSN is an environment variable resolved from a pinned version;
#  the server CA is the single mounted file.  A Cloud Run secret volume maps to
#  exactly one secret and supports no subpaths, so two secret files in
#  ${DATABASE_CA_MOUNT} would be refused client-side before anything existed.
#  There is no client certificate to mount: the migrator authenticates with a
#  password and verifies the server's CA, exactly as the runtime does.
#
#  ``--max-retries=0``: a migration that failed is a fact to read, not a thing
#  to attempt again automatically against a database whose state is now unknown.
#
#  ``muster::gcloud_container_args``: the container path below is a *container*
#  path, and on Git Bash it would not arrive as one.  See the note in env.sh.
muster::gcloud_container_args gcloud run jobs deploy "${BOOTSTRAP_JOB}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${CONTROL_PLANE_IMAGE}" \
  --service-account="${MIGRATOR_SA}" \
  --command="python" \
  --args="/app/demo/database_bootstrap.py,--cloud-sql" \
  --max-retries=0 \
  --task-timeout=600s \
  --cpu="${RUN_CPU}" \
  --memory="${RUN_MEMORY}" \
  --env-vars-file="${env_file}" \
  --set-secrets="MUSTER_MIGRATION_DATABASE_URL=${DATABASE_MIGRATION_DSN_SECRET}:${DATABASE_MIGRATION_DSN_SECRET_VERSION},${DATABASE_CA_FILE}=${DATABASE_SERVER_CA_SECRET}:${DATABASE_SERVER_CA_SECRET_VERSION}" \
  --network="${HERO_VPC_NETWORK}" \
  --subnet="${HERO_VPC_SUBNET}" \
  --vpc-egress="${HERO_VPC_EGRESS}" \
  --quiet

if [[ "${BOOTSTRAP_EXECUTE:-1}" != "1" ]]; then
  echo
  echo "  deployed and not executed (BOOTSTRAP_EXECUTE=0).  Run it with:"
  echo "      BOOTSTRAP_EXECUTE=1 $0"
  exit 0
fi

#  The read-only shape, as an argument override on the same deployed job: the
#  image, the identity, the network and the secret are the ones the migrating
#  run uses, and only the command differs.  Deploying a second job for a read
#  would be a second thing to keep in step with this one.
overrides=()
if [[ -n "${SANDBOX_EVIDENCE_KEYS:-}" && "${BOOTSTRAP_REPORT_ONLY:-0}" == "1" ]]; then
  echo "  SANDBOX_EVIDENCE_KEYS and BOOTSTRAP_REPORT_ONLY=1 ask for two reads." >&2
  echo "  Run them one at a time, so each execution's output is one answer." >&2
  exit 2
fi

if [[ -n "${SANDBOX_EVIDENCE_KEYS:-}" ]]; then
  #  Comma-separated on the way in, and comma-separated on the way out: gcloud
  #  splits --args on commas.  ``--key=K`` rather than ``--key,K``: the flag and
  #  its value as one token, because gcloud's list parser refuses a list in
  #  which the same bare token appears twice, so two keys written the other way
  #  are rejected client-side before anything is executed.  The command
  #  validates each key as 64 hex characters before it opens a connection.
  evidence_args="/app/demo/sandbox_rail_evidence.py,--cloud-sql"
  saved_ifs="${IFS}"
  IFS=','
  for key in ${SANDBOX_EVIDENCE_KEYS}; do
    evidence_args+=",--key=${key}"
  done
  IFS="${saved_ifs}"
  overrides=(--args="${evidence_args}")
  muster::banner "reading the simulated external world as ${MIGRATOR_SA}"
elif [[ "${BOOTSTRAP_REPORT_ONLY:-0}" == "1" ]]; then
  if [[ -z "${DATABASE_RUNTIME_ROLE}" ]]; then
    echo "  BOOTSTRAP_REPORT_ONLY=1 needs DATABASE_RUNTIME_ROLE to report on." >&2
    exit 2
  fi
  overrides=(--args=/app/demo/database_bootstrap.py,--cloud-sql,--report-runtime-grants)
  muster::banner "reading the runtime privileges back as ${MIGRATOR_SA}"
else
  muster::banner "running it as ${MIGRATOR_SA}"
fi

#  One execution, named by the call that created it, and read back by that name
#  alone -- the same discipline 90-hero-job.sh uses.  A migration is exactly the
#  kind of thing whose previous run's output must never be shown as this one's.
set +e
#  Wrapped for the same Git Bash reason the deploy is: these overrides carry
#  a *container* path, and unwrapped it arrived as
#  ``/app/C:/Program Files/Git/app/demo/...`` -- after the job was deployed,
#  in front of a cloud.  The exclusion is scoped to ``--args=`` and no wider.
muster::gcloud_container_args \
  muster::execute_job "${BOOTSTRAP_JOB}" ${overrides[@]+"${overrides[@]}"}
status=$?
set -e
execution="${MUSTER_EXECUTION}"

muster::banner "what it printed"
#  Content-free by construction: two comma-separated lists of integers, or a
#  refusal class.  Safe to read back and safe to show.
if ! muster::execution_output "${BOOTSTRAP_JOB}" "${execution}"; then
  echo "  the execution's output could not be read" >&2
  exit 4
fi

echo
if [[ ${status} -eq 2 ]]; then
  cat >&2 <<UNDETERMINED

  The execution's outcome could not be read, so the schema has no verdict -- not
  a negative one.  ${execution:-(no execution was named)} is what to look at:

      gcloud run jobs executions describe ${execution:-EXECUTION} \\
        --project=${PROJECT_ID} --region=${REGION}

UNDETERMINED
  exit 4
fi

if [[ ${status} -eq 0 ]]; then
  if [[ -n "${SANDBOX_EVIDENCE_KEYS:-}" ]]; then
    echo "  the simulated external world was read; nothing was written"
  elif [[ "${BOOTSTRAP_REPORT_ONLY:-0}" == "1" ]]; then
    echo "  the runtime privileges are exactly the enumerated set"
  else
    echo "  the schema is current; 90-hero-job.sh may now run with CLOUD_SQL"
  fi
  exit 0
fi

cat >&2 <<FAILED

  Execution ${execution} failed: the schema was not brought current.  Read the
  output above -- and it is that execution's output, not the job's history.

    CONFIGURATION REFUSED   the migration DSN or MUSTER_DATABASE_DEPLOYMENT is
                            absent or malformed.  The message names the variable
                            and deliberately never quotes its value.
    SCHEMA REFUSED          the ledger disagrees with this build: a migration was
                            edited in place rather than added to, or this image
                            is older than the database.  Do not "fix" this by
                            reverting the ledger; establish which build is right.
    GRANT REFUSED           ${DATABASE_RUNTIME_ROLE} does not exist, or is not a
                            plain identifier.  Create the role first; this job
                            grants to a role, it does not create one.
    RUNTIME PRIVILEGES      the grants were issued and the catalogue does not
      WRONG                 agree, or a privilege the role must NOT hold is
                            present -- an unenumerated table privilege, CREATE
                            on a schema or on the database, or ownership of a
                            runtime object.  The table above names each one.
                            Nothing was revoked: decide, then revoke by hand.
    DATABASE REFUSED        a driver failure, reported as its class.  The usual
                            causes are the VPC route to the private address, a
                            server CA that does not match the instance, and a
                            role that cannot create schema.  ${MIGRATOR_SA} must
                            own the database or hold CREATE on it.

FAILED
exit "${status}"
