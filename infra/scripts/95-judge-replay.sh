#!/usr/bin/env bash
#  Build and deploy the public judge-replay site.
#
#  This is the only MUSTER service that is deployed **unauthenticated**, and the
#  only one that may be.  What makes that safe is not a setting here; it is that
#  the image has nothing to protect.  It is a static bundle and a GET-only web
#  server: no Python, no control plane, no database, no DSN secret, no signing
#  key, no bucket access, no service-account key, and no mutation endpoint.  See
#  infra/docker/judge-replay.Dockerfile.
#
#  So the deploy below sets **no secrets, no VPC connector and no Cloud SQL
#  instance**, and it runs as a service account that has been granted nothing.
#  If a future edit needs to add one of those, that is the signal that this
#  stopped being a replay site and should stop being public.
#
#  **The runtime identity is named, and that is the point of it.**  Omitting
#  --service-account does not mean "no identity": Cloud Run falls back to the
#  project's default compute service account, which carries roles/editor unless
#  an organisation policy says otherwise.  A public, unauthenticated container
#  running as a project editor is the opposite of what the paragraph above
#  claims, and it would be true by default rather than by anybody's decision.
#  So the service runs as ``muster-judge-replay``: an account created for this
#  one purpose and given no role anywhere -- no Cloud SQL, no Storage, no
#  Secret Manager, no signing key, no project binding of any kind.  It is not
#  granted anything below and it must not be: the container serves static files
#  and needs no identity to do it, so the identity it has is the one that can
#  reach nothing.
#
#  The names it needs are defined here rather than in env.sh on purpose.
#  env.sh is the identity of the *proved* deployment -- the agent pair, the
#  control plane, the Cloud SQL custody -- and the public page is not part of
#  that system.  Keeping it out means a change here can never move a name the
#  recorded proof provenance depends on.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

: "${JUDGE_REPLAY_SERVICE:=muster-judge-replay}"
: "${JUDGE_REPLAY_IMAGE:=${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/muster-judge-replay:${IMAGE_TAG}}"
: "${JUDGE_REPLAY_SA_ID:=muster-judge-replay}"
JUDGE_REPLAY_SA="${JUDGE_REPLAY_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

#  Created here rather than in 10-identities.sh, for the same reason the names
#  above are not in env.sh: that script provisions the proved deployment's
#  principals and their asymmetric grants, and this account belongs to none of
#  it.  Idempotent, and it ends where it begins -- with an account that has no
#  binding.  There is deliberately no add-iam-policy-binding anywhere in this
#  file, and 70-verify-iam.sh is where an assertion about what it cannot reach
#  would go if one is ever wanted.
muster::banner "runtime identity ${JUDGE_REPLAY_SA_ID} (no roles)"
if gcloud iam service-accounts describe "${JUDGE_REPLAY_SA}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  exists  ${JUDGE_REPLAY_SA_ID}"
else
  gcloud iam service-accounts create "${JUDGE_REPLAY_SA_ID}" \
    --project="${PROJECT_ID}" \
    --display-name="MUSTER judge replay (static site, no grants)"
  echo "  created ${JUDGE_REPLAY_SA_ID}"
fi

muster::banner "building ${JUDGE_REPLAY_IMAGE} as ${BUILD_SA}"
gcloud builds submit "${REPOSITORY_ROOT}" \
  --project="${PROJECT_ID}" \
  --config="${REPOSITORY_ROOT}/infra/cloudbuild-judge-replay.yaml" \
  --service-account="projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA}" \
  --substitutions="_JUDGE_REPLAY_IMAGE=${JUDGE_REPLAY_IMAGE}"
echo "  built ${JUDGE_REPLAY_IMAGE}"

muster::banner "deploying ${JUDGE_REPLAY_SERVICE}"
#  --allow-unauthenticated is correct here and nowhere else in this directory.
#  --no-cpu-boost and one small instance: it serves a few hundred kilobytes.
#
#  **No --ingress flag, deliberately.**  Cloud Run's default ingress is already
#  `all`, so naming it would change nothing about this service -- and one
#  architecture test reads every script in this directory and fails if any of
#  them writes `--ingress=all`, because a script that broadened the perimeter
#  to make its own path work is exactly the failure that check exists for.
#  Keeping that rule unqualified is worth more than making this line explicit,
#  so the flag is absent and the reason is written down here instead.
gcloud run deploy "${JUDGE_REPLAY_SERVICE}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${JUDGE_REPLAY_IMAGE}" \
  --platform=managed \
  --service-account="${JUDGE_REPLAY_SA}" \
  --allow-unauthenticated \
  --port=8080 \
  --cpu=1 \
  --memory=256Mi \
  --min-instances=0 \
  --max-instances=4 \
  --timeout=30s \
  --no-cpu-boost \
  --quiet

url="$(gcloud run services describe "${JUDGE_REPLAY_SERVICE}" \
  --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')"
echo "  deployed ${url}"
echo
echo "  This page is a verified replay. It holds no credential and exposes no"
echo "  mutation endpoint. Nothing it shows is live telemetry."
