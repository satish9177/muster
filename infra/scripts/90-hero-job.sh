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
#  back through check Q-12, rebuilds, and stops at the analysis.  There is no
#  gate, nothing is authorized and nothing is settled.
#
#  It reaches the agents over **Direct VPC egress**, which is what makes its
#  call recognisable as internal traffic to a service deployed
#  ``--ingress=internal``.  That is a default here, not a repair: see the block
#  below the environment assembly, and HERO_VPC_NETWORK in env.sh.
#
#  Idempotent: the job is replaced if it exists.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

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
echo "  store     in-memory, for the life of one execution"

#  Written to a file, by the same emitter 50-deploy.sh uses -- see
#  muster::env_entry in env.sh.  The same defect was latent here: these values
#  are URLs, a ``gs://`` path and two base64 blobs, and the deploy would have
#  survived only until one of them contained the delimiter.  A public key is
#  base64 of a PEM, whose alphabet already includes '+', '/' and '='.
muster::env_file "${HERO_JOB}"
env_file="${MUSTER_ENV_FILE}"
{
  muster::env_entry MUSTER_HERO_TENANT "${TENANT_ID}"
  muster::env_entry MUSTER_HERO_CASE "${HERO_CASE_ID}"
  muster::env_entry MUSTER_HERO_SITE_ENDPOINT "${SITE_URL}"
  muster::env_entry MUSTER_HERO_EMPLOYER_ENDPOINT "${EMPLOYER_URL}"
  muster::env_entry MUSTER_HERO_SITE_KEY_REF "${SITE_KEY_REF}"
  muster::env_entry MUSTER_HERO_EMPLOYER_KEY_REF "${EMPLOYER_KEY_REF}"
  muster::env_entry MUSTER_HERO_SITE_PUBLIC_KEY "${SITE_PUBLIC}"
  muster::env_entry MUSTER_HERO_EMPLOYER_PUBLIC_KEY "${EMPLOYER_PUBLIC}"
  muster::env_entry MUSTER_HERO_RAW_OBJECT "gs://${EVIDENCE_BUCKET}/${HERO_RAW_OBJECT}"
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
trace_logs="$(mktemp "${TMPDIR:-/tmp}/muster-case-trace.XXXXXX")"
trap 'rm -f "${trace_logs}"' EXIT
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
