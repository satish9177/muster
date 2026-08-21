#!/usr/bin/env bash
#  Is the deployed agent reachable by the control plane, and by nobody else?
#
#      control-plane token, empty body   -> 400, from the agent
#      no token at all                   -> 403, from Cloud Run
#      this operator's own token         -> 403 'not_permitted', from the agent
#
#  **Told apart by the body, not by the status code.**  403 is the answer both
#  the perimeter and the agent's own allowlist give, and they are different
#  facts: one says the request never arrived, the other says it arrived and the
#  agent would not work for that caller.  Only the agent writes a one-word body.
#
#  The 400 is the first interesting one: the call arrived, the identity was
#  accepted, and the *body* was refused -- the agent's own decode refusing
#  octets that are not an assignment.  A 200 there would mean the agent answered
#  something nobody asked it.
#
#  The third is the one that matters most, and it is the check the earlier
#  version of this script could not make.  A service deployed
#  --no-allow-unauthenticated is protected by Cloud Run before the container is
#  reached, so "no token" can only ever demonstrate the perimeter -- the agent's
#  own 401 is unreachable from outside and expecting it failed every correct
#  deployment.  What *is* reachable is an identity Cloud Run admits and the
#  agent still refuses, which is the whole claim: an invoker binding is a
#  network permission and confers nothing.  It is skipped, loudly, when this
#  operator cannot invoke the service at all.
#
#  **Run this from inside the project.**  The services default to
#  ``--ingress=internal``, which refuses anything that did not originate in the
#  VPC or from another Google Cloud service here -- so a curl from a laptop is
#  rejected at the network edge, before the identity layer is reached, and both
#  checks below would be reporting on the perimeter rather than on the agent.
#  Cloud Shell inside the project, or a Compute instance, is the right place.
#
#  Read-only and idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

SERVICE="${1:-${SITE_SERVICE}}"
URL="$(gcloud run services describe "${SERVICE}" \
  --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)")"
if [[ -z "${URL}" ]]; then
  echo "  ${SERVICE} is not deployed in ${REGION}" >&2
  exit 1
fi

FAILURES=0

#  Did the *agent* write this, or the perimeter?  The agent's refusals are a
#  single lower-case word; Cloud Run's are an HTML page or a sentence.  The
#  status code cannot tell them apart, because both say 403.
muster::is_agent_body() {
  case "$1" in
    absent | invalid | invalid_token | not_permitted | "not found" | "not canonical") return 0 ;;
    *) return 1 ;;
  esac
}

muster::status_of() {
  curl --silent --output /dev/null --write-out '%{http_code}' "$@"
}

#  Distinguish the agent refusing from the perimeter refusing.  Cloud Run's
#  ingress rejection is not the app's answer, and counting it as one is how a
#  smoke test passes without smoking anything.
muster::warn_if_perimeter() {
  if [[ "${RUN_INGRESS}" == "internal" ]]; then
    echo "  NOTE  ingress is 'internal'; run this from inside ${PROJECT_ID}," >&2
    echo "        or a rejection below is the perimeter and not the agent." >&2
  fi
}

muster::warn_if_perimeter

muster::banner "authenticated, with a body that is not an assignment"
TOKEN="$(gcloud auth print-identity-token \
  --impersonate-service-account="${CONTROL_PLANE_SA}" \
  --audiences="${URL}" --include-email)"
#  The header goes in through a config file on stdin rather than on the command
#  line: an argument is visible in the process table to every other user on the
#  machine, and lands in shell history and in any log written under `set -x`.
CODE="$(printf 'header = "Authorization: Bearer %s"\n' "${TOKEN}" \
  | curl --config - \
      --silent --output /dev/null --write-out '%{http_code}' \
      -X POST "${URL}/acquire" \
      -H "Content-Type: application/octet-stream" \
      --data-binary '')"
if [[ "${CODE}" == "400" ]]; then
  echo "  PASS  ${CODE}: reached the agent, and it refused the body"
else
  echo "  FAIL  ${CODE}: expected 400"
  FAILURES=$((FAILURES + 1))
fi

muster::banner "unauthenticated"
#  Cloud Run's own refusal, before the container.  403 with no one-word body:
#  a service deployed --no-allow-unauthenticated is never reached without a
#  token, so this demonstrates the perimeter and deliberately claims no more.
BODY="$(curl --silent -X POST "${URL}/acquire" \
  -H "Content-Type: application/octet-stream" --data-binary '' || true)"
CODE="$(muster::status_of -X POST "${URL}/acquire" \
  -H "Content-Type: application/octet-stream" --data-binary '')"
if [[ "${CODE}" == "403" ]] && ! muster::is_agent_body "${BODY}"; then
  echo "  PASS  ${CODE}: Cloud Run refused a request with no identity"
elif [[ "${CODE}" == "401" || "${CODE}" == "403" ]]; then
  echo "  PASS  ${CODE}: refused, and the agent answered: ${BODY}"
else
  echo "  FAIL  ${CODE}: expected the request to be refused"
  FAILURES=$((FAILURES + 1))
fi

muster::banner "authenticated as somebody the agent does not serve"
#  The claim, as an observable: an identity Cloud Run admits, that the agent
#  still will not work for.  The operator's own account is the only such
#  identity this deployment has -- the two agent accounts hold no invoker
#  binding, so Cloud Run would refuse them at the perimeter and the answer
#  would be about the perimeter again.
OWN_TOKEN="$(gcloud auth print-identity-token --audiences="${URL}" 2>/dev/null || true)"
if [[ -z "${OWN_TOKEN}" ]]; then
  echo "  SKIPPED  this principal cannot mint an identity token for ${URL}"
else
  BODY="$(printf 'header = "Authorization: Bearer %s"\n' "${OWN_TOKEN}" \
    | curl --config - --silent -X POST "${URL}/acquire" \
        -H "Content-Type: application/octet-stream" --data-binary '' || true)"
  if [[ "${BODY}" == "not_permitted" ]]; then
    echo "  PASS  the agent reached, and refused a caller it does not serve"
  elif muster::is_agent_body "${BODY}"; then
    echo "  FAIL  the agent answered '${BODY}', not 'not_permitted'"
    FAILURES=$((FAILURES + 1))
  else
    echo "  SKIPPED  Cloud Run refused this principal before the agent saw it;"
    echo "           this operator holds no run.invoker on ${SERVICE}, so the"
    echo "           in-app allowlist cannot be exercised from here."
  fi
fi

if [[ ${FAILURES} -ne 0 ]]; then
  exit 1
fi
echo
echo "  ${SERVICE} is reachable by the control plane and by nobody else"
