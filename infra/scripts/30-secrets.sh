#!/usr/bin/env bash
#  The two source signing keys, in Secret Manager, each readable by exactly one
#  service account.
#
#    ./infra/scripts/30-secrets.sh SITE_KEY.pem EMPLOYER_KEY.pem
#
#  A source key lives with the source.  Here that means: the secret exists in
#  the project, the owning agent's service account can read it, and nothing else
#  can -- not the other agent, and not the control plane.
#
#  **No service account key is ever created or downloaded by anything here.**
#  These are the attestation keys MUSTER signs receipts with; the identity a
#  service runs as is attached to the revision and has no downloadable form.
#
#  Re-running is safe and is **not** a no-op: it adds a *new version* to an
#  existing secret.  That is a key rotation, so the script prints the version
#  it wrote and the deployment pins it -- see the note it ends with.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

usage() {
  cat >&2 <<USAGE
usage: $0 SITE_SIGNING_KEY.pem EMPLOYER_SIGNING_KEY.pem

  Each file is an EC P-256 private key in PKCS8 PEM form.  To mint a pair for a
  demo, into a directory outside this repository:

      $0 --generate /some/scratch/dir

  and register the printed public keys in the MUSTER authority registry against
  ${SITE_KEY_REF} and ${EMPLOYER_KEY_REF}.  A key whose public half the registry
  has never seen produces receipts that verify against nothing.
USAGE
  exit 2
}

#  ---- the demo key helper -------------------------------------------------
#
#  Clearly marked, and it writes nowhere near the repository.  A private key in
#  a working tree is a private key, whatever it is for.
if [[ "${1:-}" == "--generate" ]]; then
  target="${2:-}"
  [[ -n "${target}" ]] || usage
  mkdir -p "${target}"
  for name in site employer; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -outform PEM -out "${target}/${name}-signing-key.pem"
    chmod 600 "${target}/${name}-signing-key.pem"
    echo
    echo "--- ${name}: private key at ${target}/${name}-signing-key.pem"
    echo "--- ${name}: public key, register this in the authority registry"
    openssl pkey -in "${target}/${name}-signing-key.pem" -pubout
  done
  echo
  echo "now run:  $0 ${target}/site-signing-key.pem ${target}/employer-signing-key.pem"
  exit 0
fi

SITE_KEY_FILE="${1:-}"
EMPLOYER_KEY_FILE="${2:-}"
if [[ ! -f "${SITE_KEY_FILE}" || ! -f "${EMPLOYER_KEY_FILE}" ]]; then
  usage
fi

muster::store() {
  local secret="$1" file="$2" account="$3"
  if ! gcloud secrets describe "${secret}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud secrets create "${secret}" \
      --project="${PROJECT_ID}" \
      --replication-policy="user-managed" \
      --locations="${REGION}"
    echo "  created ${secret} in ${REGION}"
  fi
  gcloud secrets versions add "${secret}" \
    --project="${PROJECT_ID}" --data-file="${file}" >/dev/null
  echo "  added a version to ${secret}"
  gcloud secrets add-iam-policy-binding "${secret}" \
    --project="${PROJECT_ID}" \
    --member="serviceAccount:${account}" \
    --role="roles/secretmanager.secretAccessor" >/dev/null
  echo "  granted roles/secretmanager.secretAccessor on ${secret} to ${account} only"
}

muster::banner "source signing keys"
muster::store "${SITE_SECRET}" "${SITE_KEY_FILE}" "${SITE_SA}"
muster::store "${EMPLOYER_SECRET}" "${EMPLOYER_KEY_FILE}" "${EMPLOYER_SA}"
echo "  granted NOTHING on either secret to ${CONTROL_PLANE_SA}"

cat <<'PINNING'

  Pin the version before deploying:

      export SIGNING_KEY_VERSION=<the version printed above>

  Mounting ':latest' would let a later run of this script rotate the key that
  signs without changing MUSTER_AGENT_KEY_REF, which is the key reference the
  receipt claims signed it -- and check Q-12(b) would then refuse receipts on
  whichever instances had restarted since.  Both secrets must be at the same
  version, or deploy them one service at a time.

PINNING
