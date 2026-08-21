#!/usr/bin/env bash
#  The control plane may call the two agents, and that is the whole of what it
#  may do in this project.
#
#  Granted per service rather than at the project, because roles/run.invoker at
#  the project level is permission to invoke every Cloud Run service that will
#  ever exist here -- including ones nobody has written yet.
#
#  **This is a network permission and not authority.**  Being able to invoke the
#  site agent gives the control plane nothing to say: whether the receipt that
#  comes back may establish anything is check Q-12, decided against a signed
#  authority snapshot that has never heard of an IAM policy.
#
#  Idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::banner "invoker bindings"
for service in "${SITE_SERVICE}" "${EMPLOYER_SERVICE}"; do
  gcloud run services add-iam-policy-binding "${service}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --member="serviceAccount:${CONTROL_PLANE_SA}" \
    --role="roles/run.invoker" >/dev/null
  echo "  granted roles/run.invoker on ${service} to ${CONTROL_PLANE_SA}"
done
echo "  granted roles/run.invoker to nobody else, on nothing else"
