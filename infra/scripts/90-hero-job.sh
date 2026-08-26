#!/usr/bin/env bash
#  The worked run, as a Cloud Run job under muster-control-plane.
#
#      ./infra/scripts/90-hero-job.sh /tmp/muster-keys
#
#  The argument is the directory 30-secrets.sh minted the source keys into.
#  What this script reads from it is the **public half** of each key, which is
#  what the control plane's verifier holds; the private halves stay where they
#  are and go nowhere near this job.  If a directory holds only public keys --
#  ``site-signing-key.pub.pem`` and ``employer-signing-key.pub.pem`` -- those are
#  used directly and no private key is opened at all.
#
#  **This is the control plane, deployed as a job rather than a service.**  It
#  calls the two agents outbound and is never called, so a service would be an
#  ingress nothing needs.  It runs once, prints what happened, and exits:
#
#      0   the case reached the invariant answer
#      1   it did not, or the control plane could read raw site evidence
#      2   the arguments or the project were not usable, and nothing was deployed
#      4   an execution was created and its outcome could not be read
#
#  Four is separate from one deliberately.  "The run said no" and "we do not
#  know what the run said" are different facts, and a script that reported the
#  second as the first would be stating a verdict it does not hold.
#
#  What the job does is the production path and nothing else: it replays the
#  worked case, analyses it, tries and fails to read the site's raw object under
#  its own identity, asks the fleet over authenticated HTTPS, admits what comes
#  back through check Q-12, and rebuilds.
#
#  Where it goes after that is HERO_GATE_MODE, and it is a decision rather than
#  a default.  ANALYSIS_ONLY stops at the analysis: no gate, nothing authorized,
#  nothing settled -- the shape U1 verified.  CLOUD_SQL_ACTION_GATE_SANDBOX runs
#  the deterministic Action Gate over the same Cloud SQL custody against the
#  synthetic sandbox executor: no payment provider and no funds, and the job
#  says so on every line it prints.  The Gate mode runs its own case
#  (HERO_GATE_CASE_ID), because the analysis-only case is published evidence.
#
#  HERO_VERIFY_GATE_IDEMPOTENCY=1 runs the retry proof instead of a run: a
#  second execution that reads the lifecycle the first one recorded, confirms
#  it, and dispatches nothing.  It needs HERO_GATE_EXECUTION_ID, which the
#  first execution printed as its 'execution id', and it reads no case head at
#  all -- so it resolves the same historical execution however far the case has
#  since advanced.
#
#  HERO_GATE_REPEAT=1 runs the stronger repeat proof: the ordinary job first,
#  then the same deployed job and image digest again with
#  --repeat-gate-execution.  The second process replays the full hero path and
#  re-derives the execution identity; no HERO_GATE_EXECUTION_ID is involved.
#
#  It reaches the agents over **Direct VPC egress**, which is what makes its
#  call recognisable as internal traffic to a service deployed
#  ``--ingress=internal``.  That is a default here, not a repair: see the block
#  below the environment assembly, and HERO_VPC_NETWORK in env.sh.
#
#  Idempotent: the job is replaced if it exists.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::require_database_secret_version

#  Before anything is deployed or executed.  The interpreter is needed by the
#  *last* step this script performs -- capturing the sanitized artifact -- and
#  finding out there that it does not exist costs a real execution, real model
#  calls and a durable case, none of which the second attempt can undo.  So the
#  cheapest check in the script runs first.
muster::require_python

KEY_DIR="${1:-}"
if [[ -z "${KEY_DIR}" || ! -d "${KEY_DIR}" ]]; then
  cat >&2 <<USAGE
usage: $0 KEY_DIRECTORY

  KEY_DIRECTORY holds the source signing keys 30-secrets.sh minted:

      site-signing-key.pem       or  site-signing-key.pub.pem
      employer-signing-key.pem   or  employer-signing-key.pub.pem

  Only the public halves are read, and only the public halves are sent: they
  are what a verifier holds, and holding one grants nothing.  A private key is
  opened only to derive its public half, locally, and never leaves this machine.

USAGE
  exit 2
fi

#  ---- the public halves ---------------------------------------------------
#
#  Base64 with no line breaks, because a PEM is multi-line and the value has to
#  survive this script, a container specification and a shell.  Encoding is not
#  concealment: this is public material and the encoding is about newlines.
muster::public_key() {
  local name="$1" public="${KEY_DIR}/$1-signing-key.pub.pem" private="${KEY_DIR}/$1-signing-key.pem"
  if [[ -f "${public}" ]]; then
    openssl base64 -A -in "${public}"
    return
  fi
  if [[ ! -f "${private}" ]]; then
    echo "  no key for ${name} in ${KEY_DIR}" >&2
    exit 2
  fi
  openssl pkey -in "${private}" -pubout 2>/dev/null | openssl base64 -A
}

SITE_PUBLIC="$(muster::public_key site)"
EMPLOYER_PUBLIC="$(muster::public_key employer)"

#  ---- where the agents actually are --------------------------------------
#
#  Read from Cloud Run rather than constructed.  A service URL is assigned, and
#  a script that guessed one would produce a catalog naming an endpoint that
#  does not exist -- which the transport would refuse, correctly, with a message
#  about a host this deployment does not call.
muster::url_of() {
  gcloud run services describe "$1" \
    --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)"
}

SITE_URL="$(muster::url_of "${SITE_SERVICE}")"
EMPLOYER_URL="$(muster::url_of "${EMPLOYER_SERVICE}")"
if [[ -z "${SITE_URL}" || -z "${EMPLOYER_URL}" ]]; then
  echo "  both agents must be deployed first: run 50-deploy.sh and 60-invoker.sh" >&2
  exit 1
fi

muster::banner "hero job ${HERO_JOB}"
echo "  site      ${SITE_URL}"
echo "  employer  ${EMPLOYER_URL}"
echo "  identity  ${CONTROL_PLANE_SA}"
echo "  ingress   the agents are '--ingress=${RUN_INGRESS}'"
if [[ "${HERO_DATABASE_DEPLOYMENT}" == "CLOUD_SQL" ]]; then
  echo "  store     CLOUD_SQL -- durable, via a pinned DSN secret and the pinned server CA"
else
  echo "  store     EPHEMERAL -- in memory, for the life of one execution, and not durable"
fi
#  **Where the Gate's own configuration rules are enforced, and the only
#  place.**  env.sh defines HERO_GATE_MODE, HERO_GATE_CASE_ID and the derived
#  HERO_RUN_CASE_ID unconditionally, because bootstrap, IAM verification,
#  teardown and the source-agent deploys all source it and none of them
#  composes a Gate.  This script is the one that asks for cloud execution, so
#  this is where a mode nobody recognises, or a Gate case that collides with
#  the published analysis-only one, becomes a refusal.
muster::require_gate_configuration || exit 2

echo "  case      ${HERO_RUN_CASE_ID}"
if [[ "${HERO_GATE_MODE}" == "CLOUD_SQL_ACTION_GATE_SANDBOX" ]]; then
  echo "  mode      CLOUD_SQL + ACTION_GATE_SANDBOX -- SANDBOX: NO REAL FUNDS TRANSFERRED"
  echo "  gate      grants ${HERO_GATE_PRINCIPAL} exactly PAY, for ${TENANT_ID}"
else
  echo "  mode      ANALYSIS_ONLY -- the run stops at the analysis; no gate"
fi

#  Refused here as well as in the control plane, and for the reason every other
#  precondition in this script is checked before the deploy: a refusal that
#  arrives from inside a Cloud Run execution has already spent the model calls.
if [[ "${HERO_GATE_MODE}" == "CLOUD_SQL_ACTION_GATE_SANDBOX" \
      && "${HERO_DATABASE_DEPLOYMENT}" != "CLOUD_SQL" ]]; then
  echo "  the Action Gate mode requires HERO_DATABASE_DEPLOYMENT=CLOUD_SQL." >&2
  echo "  A durable execution lifecycle kept in memory is a proof about one" >&2
  echo "  process, and this mode exists to make a claim about a database." >&2
  exit 2
fi
if [[ "${HERO_VERIFY_GATE_IDEMPOTENCY:-0}" == "1" ]]; then
  if [[ "${HERO_GATE_MODE}" != "CLOUD_SQL_ACTION_GATE_SANDBOX" ]]; then
    echo "  the idempotency proof needs HERO_GATE_MODE=CLOUD_SQL_ACTION_GATE_SANDBOX." >&2
    exit 2
  fi
  if [[ -z "${HERO_GATE_EXECUTION_ID}" ]]; then
    echo "  the idempotency proof needs HERO_GATE_EXECUTION_ID." >&2
    echo "  It is the 'execution id' the first Gate execution printed: the" >&2
    echo "  hash of the exact authorized intent, and the durable primary key" >&2
    echo "  of its row.  A retry names that execution, not the case and not" >&2
    echo "  whatever the case currently proposes -- so it still resolves after" >&2
    echo "  the head has moved on." >&2
    exit 2
  fi
fi
if [[ "${HERO_GATE_REPEAT:-0}" == "1" \
      && "${CONTROL_PLANE_IMAGE}" != *@sha256:* ]]; then
  echo "  the repeat proof requires CONTROL_PLANE_IMAGE pinned with @sha256:." >&2
  echo "  Both executions must run the same reviewed image digest." >&2
  exit 2
fi

#  Written to a file, by the same emitter 50-deploy.sh uses -- see
#  muster::env_entry in env.sh.  The same defect was latent here: these values
#  are URLs, a ``gs://`` path and two base64 blobs, and the deploy would have
#  survived only until one of them contained the delimiter.  A public key is
#  base64 of a PEM, whose alphabet already includes '+', '/' and '='.
muster::env_file "${HERO_JOB}"
env_file="${MUSTER_ENV_FILE}"
{
  muster::env_entry MUSTER_HERO_TENANT "${TENANT_ID}"
  muster::env_entry MUSTER_HERO_CASE "${HERO_RUN_CASE_ID}"
  muster::env_entry MUSTER_HERO_SITE_ENDPOINT "${SITE_URL}"
  muster::env_entry MUSTER_HERO_EMPLOYER_ENDPOINT "${EMPLOYER_URL}"
  muster::env_entry MUSTER_HERO_SITE_KEY_REF "${SITE_KEY_REF}"
  muster::env_entry MUSTER_HERO_EMPLOYER_KEY_REF "${EMPLOYER_KEY_REF}"
  muster::env_entry MUSTER_HERO_SITE_PUBLIC_KEY "${SITE_PUBLIC}"
  muster::env_entry MUSTER_HERO_EMPLOYER_PUBLIC_KEY "${EMPLOYER_PUBLIC}"
  muster::env_entry MUSTER_HERO_RAW_OBJECT "gs://${EVIDENCE_BUCKET}/${HERO_RAW_OBJECT}"
  muster::env_entry MUSTER_DATABASE_DEPLOYMENT "${HERO_DATABASE_DEPLOYMENT}"
  muster::env_entry MUSTER_HERO_GATE_MODE "${HERO_GATE_MODE}"
  muster::env_entry MUSTER_HERO_GATE_PRINCIPAL "${HERO_GATE_PRINCIPAL}"
  muster::env_entry MUSTER_HERO_GATE_EXECUTION_ID "${HERO_GATE_EXECUTION_ID}"
  muster::env_entry MUSTER_TRACE_PROJECT_ID "${PROJECT_ID}"
  muster::env_entry MUSTER_TRACE_JOB_NAME "${HERO_JOB}"
  muster::env_entry MUSTER_TRACE_CLOUD_RUN_REGION "${REGION}"
  muster::env_entry MUSTER_TRACE_MODEL "${AGENT_MODEL}"
  muster::env_entry MUSTER_TRACE_MODEL_LOCATION "${VERTEX_LOCATION}"
  muster::env_entry MUSTER_TRACE_CONTROL_PLANE_ID "${CONTROL_PLANE_SA_ID}"
} > "${env_file}"

#  ---- Direct VPC egress, which is how this job reaches an internal agent ---
#
#  Not a remedy and not an option: it is the route.  A Cloud Run resource
#  calling a service that is ``--ingress=internal`` is recognised as internal
#  traffic only when its request leaves through a VPC network in the project.
#  Default job networking is not that route, so a job deployed without this
#  would be judged at the agent's perimeter and refused before the agent saw the
#  assignment -- a 403 from Cloud Run, arriving as ``unreached ENDPOINT_REFUSED``
#  and looking, to anyone watching, like the fleet is down rather than like a
#  network decision.
#
#  ``--vpc-egress=all-traffic`` and not ``private-ranges-only``: the destination
#  is the agent's ordinary ``run.app`` URL, a public hostname at a public
#  address, which ``private-ranges-only`` would send out by the default path --
#  arriving from outside any VPC, judged at the perimeter, exactly as if no
#  network had been attached.  The configuration would read as correct and do
#  nothing, which is the worst of the available failures.
#
#  Expanded below as ``${egress[@]+"${egress[@]}"}`` rather than
#  ``"${egress[@]}"``: under ``set -u`` the plain form is an unbound-variable
#  error for an empty array on bash 3.2, which is the bash an operator on macOS
#  has -- and the array is empty on the diagnostic path just below.
egress=()
if [[ -n "${HERO_VPC_NETWORK}" && -n "${HERO_VPC_SUBNET}" ]]; then
  egress=(
    --network="${HERO_VPC_NETWORK}"
    --subnet="${HERO_VPC_SUBNET}"
    --vpc-egress="${HERO_VPC_EGRESS}"
  )
  echo "  egress    ${HERO_VPC_EGRESS} via ${HERO_VPC_NETWORK}/${HERO_VPC_SUBNET}"
else
  #  Reached only by emptying HERO_VPC_NETWORK or HERO_VPC_SUBNET deliberately,
  #  which is a diagnostic and not a configuration: it establishes whether a
  #  failure is the network perimeter or something above it.
  echo "  egress    DEFAULT -- no VPC network attached" >&2
  echo "            This is a diagnostic path.  The agents are '--ingress=${RUN_INGRESS}'," >&2
  echo "            and an internal agent will refuse this job at the perimeter." >&2
fi

#  ---- and the half of that route nobody had written down ------------------
#
#  ``all-traffic`` puts every packet through the subnet, and a Cloud Run
#  instance on Direct VPC egress has no external address -- so the subnet has to
#  have **Private Google Access** or those packets have nowhere to go.  This
#  deployment already paid for that being unwritten: an execution that reached
#  nothing, hung on its first outbound call, and was killed with
#
#      Terminating task because it has reached the maximum timeout of 900 seconds.
#
#  It was made to work by hand, on a subnet, once -- which is a cloud
#  prerequisite living outside these scripts and therefore missing in the next
#  project.  ``muster::require_private_google_access`` establishes it or refuses
#  with the exact command, and it runs *before* the deploy below so that a
#  refusal has created nothing.  Called unconditionally: it decides for itself
#  that the diagnostic path and ``private-ranges-only`` do not need it, which is
#  a decision belonging next to the reason rather than in a caller's branch.
muster::require_private_google_access

#  ``jobs deploy`` creates or updates, which is what makes this re-runnable.
#  ``--max-retries=0``: a run that failed is a result, and retrying it would
#  spend model calls to produce a second copy of the same answer.
#  ---- what the run is given to reach a database with ----------------------
#
#  Two secrets under CLOUD_SQL and none under EPHEMERAL, expanded the same way
#  ``egress`` is and for the same bash 3.2 reason.
#
#  **One secret per mounted directory.**  A Cloud Run secret volume maps to
#  exactly one secret and supports no subpaths, so a second secret file under
#  ${DATABASE_CA_MOUNT} would not be a tighter layout -- gcloud refuses it,
#  client-side, before anything is created:
#
#      Cannot update secret at [...] because a different secret is already
#      mounted in the same directory.
#
#  Only the server CA is a file, so one directory is enough.  The DSN, which
#  carries the password, is a secret-backed *environment variable*: Cloud Run
#  resolves the pinned version into MUSTER_DATABASE_URL directly, so the value
#  never passes through this script, the env-vars file, or an argument list.
secrets=()
if [[ "${HERO_DATABASE_DEPLOYMENT}" == "CLOUD_SQL" ]]; then
  secrets=(
    --set-secrets="MUSTER_DATABASE_URL=${DATABASE_DSN_SECRET}:${DATABASE_DSN_SECRET_VERSION},${DATABASE_CA_FILE}=${DATABASE_SERVER_CA_SECRET}:${DATABASE_SERVER_CA_SECRET_VERSION}"
  )
else
  #  Not "no flag".  An EPHEMERAL redeploy of a job that was CLOUD_SQL has to
  #  take the old mount off, or the run would keep a credential its custody no
  #  longer names -- and `jobs deploy` updates in place rather than replacing.
  secrets=(--clear-secrets)
fi

gcloud run jobs deploy "${HERO_JOB}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${CONTROL_PLANE_IMAGE}" \
  --service-account="${CONTROL_PLANE_SA}" \
  --max-retries=0 \
  --task-timeout=900s \
  --cpu="${RUN_CPU}" \
  --memory="${RUN_MEMORY}" \
  --env-vars-file="${env_file}" \
  ${secrets[@]+"${secrets[@]}"} \
  ${egress[@]+"${egress[@]}"} \
  --quiet

#  Deployed and not run.  What is printed here is this script again rather than
#  a gcloud line, deliberately: a hand-run execution is one whose name nobody
#  kept, and reading a job's logs without one is how a previous execution's
#  output came to be shown as this run's.  Re-running this is idempotent -- the
#  job is replaced -- and it ends holding the name.
if [[ "${HERO_EXECUTE:-1}" != "1" ]]; then
  echo
  echo "  deployed and not executed (HERO_EXECUTE=0).  Run it with:"
  echo "      HERO_EXECUTE=1 $0 ${KEY_DIR}"
  exit 0
fi

#  The exact-repeat proof is two executions of this one deployed job, with no
#  deploy between them.  The first uses the job's ordinary entry point.  The
#  second changes only the container argument, asking the same image digest to
#  replay the full case and call the same ActionGate.execute path again.
if [[ "${HERO_GATE_REPEAT:-0}" == "1" ]]; then
  muster::banner "running the first gate execution as ${CONTROL_PLANE_SA}"
  set +e
  muster::execute_job "${HERO_JOB}"
  first_status=$?
  set -e
  first_execution="${MUSTER_EXECUTION}"

  muster::banner "repeating the full gate execution as ${CONTROL_PLANE_SA}"
  set +e
  muster::execute_job "${HERO_JOB}" --args="--repeat-gate-execution"
  repeat_status=$?
  set -e
  repeat_execution="${MUSTER_EXECUTION}"

  first_logs="$(mktemp "${TMPDIR:-/tmp}/muster-gate-first.XXXXXX")"
  repeat_logs="$(mktemp "${TMPDIR:-/tmp}/muster-gate-repeat.XXXXXX")"
  trap 'rm -f "${first_logs}" "${repeat_logs}"; muster::env_cleanup' EXIT
  first_read=1
  repeat_read=1
  if ! muster::execution_output "${HERO_JOB}" "${first_execution}" > "${first_logs}"; then
    first_read=0
  fi
  if ! muster::execution_output "${HERO_JOB}" "${repeat_execution}" > "${repeat_logs}"; then
    repeat_read=0
  fi

  muster::banner "what the first execution printed"
  [[ ! -s "${first_logs}" ]] || cat "${first_logs}"
  muster::banner "what the repeat execution printed"
  [[ ! -s "${repeat_logs}" ]] || cat "${repeat_logs}"

  if [[ ${first_status} -eq 2 || ${repeat_status} -eq 2 \
        || ${first_read} -ne 1 || ${repeat_read} -ne 1 ]]; then
    {
      echo "  One or both execution outputs could not be read, so the exact-repeat"
      echo "  result is UNDETERMINED.  Nothing is claimed about duplicate prevention."
    } >&2
    exit 4
  fi
  if [[ ${first_status} -ne 0 || ${repeat_status} -ne 0 ]]; then
    echo "  the exact-repeat proof was not established; read both outputs above" >&2
    exit 1
  fi

  first_id="$(sed -n 's/^[[:space:]]*execution id[[:space:]]*//p' "${first_logs}" | tail -n 1)"
  repeat_id="$(sed -n 's/^[[:space:]]*execution id[[:space:]]*//p' "${repeat_logs}" | tail -n 1)"
  first_reference="$(sed -n 's/^[[:space:]]*external reference[[:space:]]*//p' "${first_logs}" | tail -n 1)"
  repeat_reference="$(sed -n 's/^[[:space:]]*external reference[[:space:]]*//p' "${repeat_logs}" | tail -n 1)"
  first_state="$(sed -n 's/^[[:space:]]*state[[:space:]]*//p' "${first_logs}" | tail -n 1)"
  repeat_state="$(sed -n 's/^[[:space:]]*state[[:space:]]*//p' "${repeat_logs}" | tail -n 1)"
  first_dispatches="$(sed -n 's/^[[:space:]]*dispatches this run[[:space:]]*//p' "${first_logs}" | tail -n 1)"
  repeat_dispatches="$(sed -n 's/^[[:space:]]*dispatches this run[[:space:]]*//p' "${repeat_logs}" | tail -n 1)"

  if [[ -z "${first_id}" || -z "${repeat_id}" \
        || -z "${first_reference}" || -z "${repeat_reference}" \
        || -z "${first_state}" || -z "${repeat_state}" \
        || -z "${first_dispatches}" || -z "${repeat_dispatches}" ]]; then
    echo "  The execution outputs were incomplete, so the exact-repeat result is UNDETERMINED." >&2
    exit 4
  fi
  if [[ "${first_id}" != "${repeat_id}" \
        || "${first_reference}" != "${repeat_reference}" \
        || "${first_state}" != "CONFIRMED" \
        || "${repeat_state}" != "CONFIRMED" \
        || "${first_dispatches}" != "1" \
        || "${repeat_dispatches}" != "0" ]]; then
    echo "  the two executions did not establish exact-repeat idempotency" >&2
    exit 1
  fi

  echo "  exact repeat re-derived ${repeat_id}; one dispatch across both executions"
  exit 0
fi

#  The retry proof is a *different invocation of the same job*, deliberately:
#  a second Cloud Run execution, a second process, a second connection, and no
#  shared memory with the first.  That is the whole claim -- an idempotency read
#  that only worked inside the process that executed would be no claim at all.
#
#  ``--args`` carries the flag and **not** the script path.  The control-plane
#  image's ENTRYPOINT is already ``["python", "/app/demo/cloud_hero.py"]``, and
#  Cloud Run appends the container args to it: naming the script here as well
#  -- which is what 85-database-bootstrap.sh does, correctly, because that job
#  overrides the command with ``--command="python"`` -- would run
#
#      python /app/demo/cloud_hero.py /app/demo/cloud_hero.py --verify-...
#
#  and argparse would refuse an argument nobody meant to pass.  There is also
#  no leading '/' in the value, so the Git Bash path rewriting that
#  ``muster::gcloud_container_args`` exists for cannot apply to it.
if [[ "${HERO_VERIFY_GATE_IDEMPOTENCY:-0}" == "1" ]]; then
  muster::banner "verifying gate idempotency as ${CONTROL_PLANE_SA}"
  set +e
  muster::execute_job "${HERO_JOB}" --args="--verify-gate-idempotency"
  status=$?
  set -e
  execution="${MUSTER_EXECUTION}"

  muster::banner "what it printed"
  #  The proof is what this execution *printed*, and reading it is required
  #  rather than attempted.
  #
  #  A Cloud Run execution that succeeded is not by itself a duplicate-prevention
  #  proof: the claim being made is that the retry read a durable CONFIRMED row
  #  and dispatched nothing, and every term of that claim -- the state, the
  #  execution id, ``dispatches this run 0`` -- lives in the output.  An exit
  #  status of zero with no readable output says a process ended well and says
  #  nothing about what it decided, so printing the proof line off that alone
  #  would be asserting the thing this stage exists to demonstrate.
  #
  #  Unreadable output is therefore undetermined, not negative and not proved:
  #  the same exit 4 the evidence path below returns when it cannot read what it
  #  is bound to.  Scoped to ${execution} for the reason that path is scoped.
  #  Bash keeps one EXIT trap, so this handler has to do everything the one it
  #  replaces did.  ``muster::env_file`` installed ``muster::env_cleanup`` on
  #  EXIT when it made MUSTER_ENV_DIR, and a bare ``rm -f`` here would silently
  #  disarm it -- leaving the 0700 directory holding this job's env-vars file
  #  behind on every run, which is the one thing env.sh's own note promises does
  #  not happen.  ``muster::env_cleanup`` is idempotent and returns 0, so
  #  calling it here and from the INT/TERM handlers costs nothing.
  retry_logs="$(mktemp "${TMPDIR:-/tmp}/muster-gate-retry.XXXXXX")"
  trap 'rm -f "${retry_logs}"; muster::env_cleanup' EXIT
  retry_read=1
  if ! muster::execution_output "${HERO_JOB}" "${execution}" > "${retry_logs}"; then
    retry_read=0
  fi
  if [[ -s "${retry_logs}" ]]; then
    cat "${retry_logs}"
  fi

  echo
  if [[ ${status} -eq 2 ]]; then
    cat >&2 <<UNDETERMINED

  The retry's outcome could not be read, so this run has no verdict about
  idempotency -- not a negative one.  ${execution:-(no execution was named)} is
  what to look at:

      gcloud run jobs executions describe ${execution:-EXECUTION} \
        --project=${PROJECT_ID} --region=${REGION}

UNDETERMINED
    exit 4
  fi

  if [[ ${status} -eq 0 ]]; then
    if [[ ${retry_read} -ne 1 ]]; then
      {
        echo "  the retry execution succeeded, but its own output could not be read, so"
        echo "  whether anything was dispatched is undetermined.  Nothing is claimed:"
        echo "      gcloud run jobs executions describe ${execution} \\"
        echo "        --project=${PROJECT_ID} --region=${REGION}"
      } >&2
      exit 4
    fi
    echo "  the durable execution was already CONFIRMED, and nothing was dispatched"
    exit 0
  fi
  echo "  the idempotency proof was not established; read ${execution} above" >&2
  exit "${status}"
fi

muster::banner "running it as ${CONTROL_PLANE_SA}"
#  One execution, named by the call that created it.  ``muster::execute_job``
#  leaves that name in MUSTER_EXECUTION and waits for that execution alone --
#  see the long note in env.sh for what the previous ``--wait`` plus job-wide
#  log read did instead, and why a real line from the wrong run is the worst
#  thing an evidence path can print.
set +e
muster::execute_job "${HERO_JOB}"
status=$?
set -e
execution="${MUSTER_EXECUTION}"

muster::banner "what it printed"
#  The job's own output is the artifact.  It is content-free by construction --
#  predicate names, identifiers, digests, enum values and counts -- so it is
#  safe to read back here and safe to show.
#
#  Scoped to ${execution}, and to nothing else.  Keep the exact bytes that are
#  shown, because the machine record is captured from this same bounded read --
#  never from a second query that might observe a different ingestion state.
#  Chained to ``muster::env_cleanup`` for the reason spelled out at the retry
#  branch above: one EXIT trap, so replacing it means re-installing what it did.
trace_logs="$(mktemp "${TMPDIR:-/tmp}/muster-case-trace.XXXXXX")"
trap 'rm -f "${trace_logs}"; muster::env_cleanup' EXIT
logs_read=1
if ! muster::execution_output "${HERO_JOB}" "${execution}" > "${trace_logs}"; then
  logs_read=0
fi
if [[ -s "${trace_logs}" ]]; then
  cat "${trace_logs}"
fi

echo
if [[ ${status} -eq 2 ]]; then
  cat >&2 <<UNDETERMINED

  The execution's outcome could not be read, so this run has no verdict -- not a
  negative one.  ${execution:-(no execution was named)} is what to look at:

      gcloud run jobs executions describe ${execution:-EXECUTION} \\
        --project=${PROJECT_ID} --region=${REGION}

UNDETERMINED
  exit 4
fi

if [[ ${status} -eq 0 ]]; then
  if [[ ${logs_read} -ne 1 ]]; then
    echo "  the execution succeeded but its artifact-bearing output was unavailable" >&2
    exit 4
  fi

  execution_times="$(gcloud run jobs executions describe "${execution}" \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --format="value(status.startTime,status.completionTime)" 2>/dev/null || true)"
  read -r executed_at completed_at <<< "${execution_times}"
  if [[ -z "${executed_at:-}" || -z "${completed_at:-}" ]]; then
    echo "  ${execution} succeeded but its execution timestamps could not be bound" >&2
    exit 4
  fi

  artifact_output="${EVIDENCE_DIR}/case-traces/${execution}.json"
  ui_output="${REPOSITORY_ROOT}/packages/muster-ui/public/cases/ravi-cloud-execution.json"
  if ! "${MUSTER_PYTHON}" "${REPOSITORY_ROOT}/infra/scripts/capture_case_trace.py" \
    --logs "${trace_logs}" \
    --project "${PROJECT_ID}" \
    --job "${HERO_JOB}" \
    --region "${REGION}" \
    --execution "${execution}" \
    --executed-at "${executed_at}" \
    --completed-at "${completed_at}" \
    --output "${artifact_output}" \
    --ui-output "${ui_output}"; then
    echo "  ${execution} succeeded but no valid sanitized case trace was captured" >&2
    exit 4
  fi
  echo "  the case reached the invariant answer"
  exit 0
fi
cat >&2 <<FAILED

  Execution ${execution} failed: the case did not reach the invariant answer, or
  the control plane could read raw site evidence.  Read the output above -- and
  it is that execution's output, not the job's history.

    raw-object ALLOWED    the boundary does not hold.  Re-run 20-site-evidence.sh
                          and 70-verify-iam.sh; do not grant the control plane
                          anything to "fix" this.
    unreached  ENDPOINT_*  the agents were not reachable from this job.  The
                          usual cause is the VPC path: confirm the job carries
                          --network/--subnet/--vpc-egress=all-traffic, that
                          ${HERO_VPC_NETWORK}/${HERO_VPC_SUBNET} exist in
                          ${REGION}, and that compute.googleapis.com is enabled.
    abstained  *           a source declined.  Its own logs say why; the reason
                          is deliberately not carried across the boundary.
    refused    ADMISSION_REFUSED
                          a receipt was authentic and unauthorized.  The registry
                          does not grant ${SITE_KEY_REF} or ${EMPLOYER_KEY_REF}
                          what the agent signed for.
    (no output, and a
     'maximum timeout' line)
                          the job reached nothing at all and was killed by its own
                          task timeout.  That is the network, one layer below the
                          perimeter: with --vpc-egress=${HERO_VPC_EGRESS} every packet
                          leaves through ${HERO_VPC_SUBNET}, and an instance there has
                          no external address, so Private Google Access has to be on
                          for it.  This script checks and sets that before deploying;
                          a run that still shows this had it turned off underneath.

FAILED
exit "${status}"
