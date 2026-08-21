#!/usr/bin/env bash
#  The private evidence bucket, and the IAM policy that is the whole claim.
#
#  After this script:
#    * the site agent can read objects under site-a/ and nothing else;
#    * the employer agent can read objects under employer-1/ and nothing else;
#    * the control plane can read NOTHING in this bucket.
#
#  That last line is not an omission and must not be "fixed".  It is the
#  observable 70-verify-iam.sh exists to capture: the control plane does not
#  hold back the site's material out of politeness, it cannot reach it.
#
#  Idempotent: the bucket is created if absent, objects are overwritten, and
#  IAM bindings are add-only and repeat harmlessly.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::banner "private evidence bucket gs://${EVIDENCE_BUCKET}"
if gcloud storage buckets describe "gs://${EVIDENCE_BUCKET}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "  exists"
else
  gcloud storage buckets create "gs://${EVIDENCE_BUCKET}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --uniform-bucket-level-access \
    --public-access-prevention
  echo "  created in ${REGION}"
fi

muster::banner "uploading synthetic material"
gcloud storage cp "${FIXTURES}/site-a/"* "gs://${EVIDENCE_BUCKET}/${SITE_PREFIX}/" \
  --project="${PROJECT_ID}"
gcloud storage cp "${FIXTURES}/employer-1/"* "gs://${EVIDENCE_BUCKET}/${EMPLOYER_PREFIX}/" \
  --project="${PROJECT_ID}"

#  A conditional binding, so the grant is over one prefix rather than over the
#  whole bucket.  An object's resource name is the full path, which is why the
#  expression anchors on the objects/ segment: a condition written against the
#  bare prefix would also match a bucket whose name began with it.
muster::grant_prefix() {
  local account="$1" prefix="$2" title="$3"
  local expression
  expression="resource.name.startsWith('projects/_/buckets/${EVIDENCE_BUCKET}/objects/${prefix}/')"
  gcloud storage buckets add-iam-policy-binding "gs://${EVIDENCE_BUCKET}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${account}" \
    --role="roles/storage.objectViewer" \
    --condition="title=${title},expression=${expression}" >/dev/null
  echo "  granted roles/storage.objectViewer to ${account} over ${prefix}/ only"
}

muster::banner "who may read what"
muster::grant_prefix "${SITE_SA}" "${SITE_PREFIX}" "site-a-material-only"
muster::grant_prefix "${EMPLOYER_SA}" "${EMPLOYER_PREFIX}" "employer-1-material-only"
echo "  granted NOTHING to ${CONTROL_PLANE_SA} -- deliberately, and permanently"
