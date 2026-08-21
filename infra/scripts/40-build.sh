#!/usr/bin/env bash
#  One image, built from the repository root so the package directories are in
#  the build context.  Idempotent: the repository is created if absent and the
#  build overwrites the tag.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::banner "artifact registry ${REPO}"
if gcloud artifacts repositories describe "${REPO}" \
    --project="${PROJECT_ID}" --location="${REGION}" >/dev/null 2>&1; then
  echo "  exists"
else
  gcloud artifacts repositories create "${REPO}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --repository-format=docker \
    --description="MUSTER agent images"
  echo "  created"
fi

muster::banner "building ${IMAGE} and ${CONTROL_PLANE_IMAGE} as ${BUILD_SA}"
#  A build config rather than a bare --tag, because the Dockerfile is not at the
#  root of the build context: the context has to be the repository, so that the
#  package directories are visible, while the Dockerfile lives under infra.
#
#  **--service-account is the whole reason muster-build exists.**  Without it a
#  build runs as the project's default build or compute service account, and in
#  most projects the compute default carries roles/editor -- which includes
#  project-wide object reads.  A build could then read the evidence bucket, and
#  so could anybody able to start one: a path straight around every prefix
#  condition 20-site-evidence.sh writes.  10-identities.sh created the identity
#  and granted it exactly two roles; this is the line that uses it.
#
#  CLOUD_LOGGING_ONLY in the build config is a requirement of this flag rather
#  than a preference: a build running as a user-specified account may not write
#  to the legacy default logs bucket.
#
#  If the build refuses because this principal may not act as that account, the
#  fix is to grant it -- never to drop the flag:
#
#      gcloud iam service-accounts add-iam-policy-binding "${BUILD_SA}" \
#        --project="${PROJECT_ID}" --member="user:YOU" \
#        --role=roles/iam.serviceAccountUser
gcloud builds submit "${REPOSITORY_ROOT}" \
  --project="${PROJECT_ID}" \
  --config="${REPOSITORY_ROOT}/infra/cloudbuild.yaml" \
  --service-account="projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA}" \
  --substitutions="_IMAGE=${IMAGE},_CONTROL_PLANE_IMAGE=${CONTROL_PLANE_IMAGE}"
echo "  built ${IMAGE}"
echo "  built ${CONTROL_PLANE_IMAGE}"
