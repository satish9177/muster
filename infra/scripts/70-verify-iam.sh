#!/usr/bin/env bash
#  The proof.  Attempts under two identities, against the real storage layer,
#  with the real outcome recorded.
#
#      control plane -> the site's gate log     MUST be denied
#      site agent    -> the site's gate log     MUST succeed
#      employer agent-> the site's gate log     MUST be denied
#      control plane -> the site's signing key  MUST be denied
#      site agent    -> the site's signing key  MUST succeed
#
#  The third and fifth are what make the others mean something.  A denial
#  proves nothing on its own -- a principal that does not exist is denied, a
#  bucket that does not exist is denied, an object nobody uploaded is denied --
#  so every denial here is paired with an *allow* that proves the resource is
#  there and reachable.  Without the employer check in particular, nothing
#  distinguishes "granted on the site-a/ prefix only" from "granted on the
#  whole bucket": the control plane holds no binding at all and would be
#  refused either way.
#
#  **A denial for the wrong reason is a failure, not a pass.**  Impersonation
#  needs its own grant, and a caller who lacks it gets ``PERMISSION_DENIED``
#  from the IAM Credentials API -- the same words Cloud Storage uses, before
#  any request reaches Cloud Storage at all.  A typo in a service account name
#  produces the same text.  So this script proves it can impersonate each
#  identity *first*, and refuses to count a token-minting failure as evidence
#  of anything.
#
#  Nothing here simulates anything.  There is no flag that prints a denial
#  without making the call, and no branch that decides the verdict from
#  configuration.  The exit code is the assertion: non-zero unless every
#  expectation held, and in particular non-zero if the control plane turns out
#  to be *able* to read the site's material.
#
#  Idempotent, and read-only: it grants nothing and changes nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

mkdir -p "${EVIDENCE_DIR}"
LOG="${EVIDENCE_DIR}/iam-verification.txt"

SITE_OBJECT="gs://${EVIDENCE_BUCKET}/${SITE_PREFIX}/gate-log-sat.txt"
FAILURES=0

#  What a *storage or secret* refusal looks like, as opposed to a failure to
#  mint a token.  Narrow on purpose: the generic word "permission" appears in
#  both, and matching it is how a verification script passes without verifying.
DENIAL='storage.objects.get|secretmanager.versions.access|does not have storage|403'
#  What a failure to impersonate looks like.  Never a pass, under any heading.
NOT_A_DENIAL='iam.serviceAccounts.getAccessToken|IAM Service Account Credentials'

muster::record() {
  printf '\n=== %s\n' "$*" >>"${LOG}"
}

#  Prove the principal exists and that this caller can act as it.  Both, before
#  any assertion runs: a missing account and a missing grant each produce a
#  denial that would otherwise be counted as the boundary holding.
muster::require_impersonation() {
  local account="$1"
  if ! gcloud iam service-accounts describe "${account}" \
      --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  FAIL  ${account} does not exist; run 10-identities.sh first" >&2
    exit 1
  fi
  if ! gcloud auth print-access-token \
      --impersonate-service-account="${account}" >/dev/null 2>&1; then
    cat >&2 <<GRANT
  FAIL  this principal cannot impersonate ${account}, so nothing below would be
        evidence.  Grant it and re-run:

      gcloud iam service-accounts add-iam-policy-binding ${account} \\
        --project=${PROJECT_ID} \\
        --member="user:\$(gcloud config get-value account)" \\
        --role=roles/iam.serviceAccountTokenCreator

GRANT
    exit 1
  fi
}

#  Expect a denial.  A success here is a failure of the deployment; a failure
#  for any other reason is not evidence of isolation either.
muster::expect_denied() {
  local account="$1" what="$2"
  shift 2
  local output status
  muster::record "as ${account}: ${what} -- expecting a permission denial"
  set +e
  output="$("$@" --impersonate-service-account="${account}" 2>&1)"
  status=$?
  set -e
  #  The *outcome* is recorded, never the object.  Writing the body here would
  #  put one site's raw material into the repository, which is the leak the
  #  bucket policy above exists to prevent.
  printf 'exit status: %s\n' "${status}" >>"${LOG}"
  printf 'response: %s\n' "$(printf '%s' "${output}" | head -c 400 | tr '\n' ' ')" >>"${LOG}"

  if [[ ${status} -eq 0 ]]; then
    echo "  FAIL  ${account} CAN reach ${what}; the boundary does not hold"
    FAILURES=$((FAILURES + 1))
    return
  fi
  if printf '%s' "${output}" | grep -qE "${NOT_A_DENIAL}"; then
    echo "  FAIL  ${account} could not mint a token for ${what}; this is not a denial"
    FAILURES=$((FAILURES + 1))
    return
  fi
  if printf '%s' "${output}" | grep -qiE "${DENIAL}"; then
    echo "  PASS  ${account} is denied ${what}"
    return
  fi
  echo "  FAIL  ${account} failed on ${what}, and not with a permission denial:"
  printf '        %s\n' "${output}" | head -3
  FAILURES=$((FAILURES + 1))
}

#  Expect success, and record that it succeeded rather than what it returned.
muster::expect_allowed() {
  local account="$1" what="$2"
  shift 2
  local status octets
  muster::record "as ${account}: ${what} -- expecting success"
  set +e
  octets="$("$@" --impersonate-service-account="${account}" 2>/dev/null | wc -c)"
  status=${PIPESTATUS[0]}
  set -e
  printf 'exit status: %s, %s octets read\n' "${status}" "${octets}" >>"${LOG}"
  if [[ ${status} -eq 0 && ${octets} -gt 0 ]]; then
    echo "  PASS  ${account} can read ${what} (${octets} octets)"
    return
  fi
  echo "  FAIL  ${account} cannot read ${what}"
  FAILURES=$((FAILURES + 1))
}

{
  printf 'MUSTER IAM verification\n'
  printf 'project : %s\n' "${PROJECT_ID}"
  printf 'region  : %s\n' "${REGION}"
  printf 'bucket  : gs://%s\n' "${EVIDENCE_BUCKET}"
  printf 'run at  : %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '\nNo object body is recorded here, only outcomes: this file lives in the\n'
  printf 'repository, and the material it is about must not.\n'
} >"${LOG}"

muster::require_impersonation "${CONTROL_PLANE_SA}"
muster::require_impersonation "${SITE_SA}"
muster::require_impersonation "${EMPLOYER_SA}"

muster::banner "raw site evidence"
muster::expect_denied "${CONTROL_PLANE_SA}" "${SITE_OBJECT}" \
  gcloud storage cat "${SITE_OBJECT}" --project="${PROJECT_ID}"
muster::expect_allowed "${SITE_SA}" "${SITE_OBJECT}" \
  gcloud storage cat "${SITE_OBJECT}" --project="${PROJECT_ID}"
#  The check that makes the prefix condition mean something: another agent,
#  holding a real grant on this same bucket, still cannot read the site's.
muster::expect_denied "${EMPLOYER_SA}" "${SITE_OBJECT}" \
  gcloud storage cat "${SITE_OBJECT}" --project="${PROJECT_ID}"

muster::banner "the site's signing key"
muster::expect_denied "${CONTROL_PLANE_SA}" "secret ${SITE_SECRET}" \
  gcloud secrets versions access latest --secret="${SITE_SECRET}" --project="${PROJECT_ID}"
muster::expect_allowed "${SITE_SA}" "secret ${SITE_SECRET}" \
  gcloud secrets versions access latest --secret="${SITE_SECRET}" --project="${PROJECT_ID}"

echo
echo "  evidence written to ${LOG}"
if [[ ${FAILURES} -ne 0 ]]; then
  echo "  ${FAILURES} check(s) did not hold; this is not the deployment the architecture describes" >&2
  exit 1
fi
echo "  every check held"
