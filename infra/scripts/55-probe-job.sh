#!/usr/bin/env bash
#  Deploy the denial as a *running process*, not only as an assertion an
#  operator can make from their laptop.
#
#  70-verify-iam.sh impersonates the control-plane service account and proves
#  that account cannot read the site's material.  That is a true statement
#  about an identity.  What this adds is the statement about a **process**: a
#  Cloud Run job, in the project, running the agent image under
#  ``muster-control-plane``, doing exactly what the control plane would do if it
#  tried -- and exiting 3, because Cloud Storage refuses it.
#
#  The distinction is worth a script.  "The control plane physically cannot read
#  raw site evidence" is a claim about something that runs; proving it only by
#  impersonation leaves open the reading where the control plane runs somewhere
#  else, under somebody's own credentials, and is not covered at all.
#
#  Exit codes come from ``muster-agent-probe``:
#      0 readable   3 denied   4 absent   5 unavailable
#  A green run of this script is exit **3**.
#
#  Idempotent: the job is replaced if it exists.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

OBJECT="${1:-gate-log-sat.txt}"

muster::banner "control-plane probe job"
#  ``jobs deploy`` creates or updates, which is what makes this re-runnable.
#  The job runs the same image the agents run and a different entrypoint: one
#  image, so what is proven is about the identity rather than about the code.
gcloud run jobs deploy "${PROBE_JOB}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE}" \
  --service-account="${CONTROL_PLANE_SA}" \
  --command="muster-agent-probe" \
  --args="gs://${EVIDENCE_BUCKET}/${SITE_PREFIX},${OBJECT}" \
  --max-retries=0 \
  --task-timeout=60s \
  --quiet

muster::banner "running it as ${CONTROL_PLANE_SA}"
#  Through the shared runner, so the execution this proves something about is
#  the one this invocation created -- a job accumulates executions, and evidence
#  attributed to the wrong one is worse than no evidence.  See env.sh.
set +e
muster::execute_job "${PROBE_JOB}"
status=$?
set -e
execution="${MUSTER_EXECUTION}"

mkdir -p "${EVIDENCE_DIR}"
{
  printf '\n=== control-plane probe job\n'
  printf 'job     : %s\n' "${PROBE_JOB}"
  #  Recorded, because "the probe was denied" is a claim about one run and the
  #  file it goes into is appended to on every re-run.
  printf 'execution: %s\n' "${execution:-(none named)}"
  printf 'identity: %s\n' "${CONTROL_PLANE_SA}"
  printf 'object  : gs://%s/%s/%s\n' "${EVIDENCE_BUCKET}" "${SITE_PREFIX}" "${OBJECT}"
  printf 'execution exit status: %s\n' "${status}"
} >>"${EVIDENCE_DIR}/iam-verification.txt"

if [[ ${status} -eq 2 ]]; then
  echo "  the execution's outcome could not be read, so this run proves nothing" >&2
  echo "  either way.  Nothing above is a denial and nothing above is a read." >&2
  exit 4
fi

if [[ ${status} -eq 0 ]]; then
  echo "  FAIL  the control plane's own process READ the site's material" >&2
  echo "        Read that execution's logs; something granted it access." >&2
  exit 1
fi

cat <<GUIDANCE

  The job failed, which is the expected result.  Confirm it failed for the right
  reason -- the probe prints DENIED to stderr and exits 3 -- with a read scoped
  to the execution this run created, and not to the job:

      gcloud logging read \\
        'resource.type="cloud_run_job"
         AND resource.labels.job_name="${PROBE_JOB}"
         AND labels."run.googleapis.com/execution_name"="${execution}"' \\
        --project=${PROJECT_ID} --limit=200 --order=asc --format='value(textPayload)'

  A line beginning DENIED is the evidence.  ABSENT or UNAVAILABLE means the
  object or the bucket is wrong and this run proves nothing.  Without the
  execution clause the read spans every execution this job has ever had, and an
  earlier one's DENIED would read as this one's.

GUIDANCE
