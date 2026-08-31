#!/usr/bin/env bash
#  Deploy the two acquisition agents, each under its own identity.
#
#  Two passes, and the second one is not a mistake.  A service's identity token
#  audience is its own URL, and a service does not have a URL until it has been
#  deployed once -- so the first pass creates it and the second tells it what it
#  is called.  Doing it in one pass would mean guessing the URL.
#
#  **Pass one carries a placeholder audience, and "neither" is not an option
#  here.**  The container refuses to start with one of the pair and not the
#  other; it *also* refuses to start when a deployed service (one with
#  ``K_SERVICE`` set, which is every Cloud Run revision) names no audience at
#  all -- because such a revision would have a port, a signing key and no
#  identity check.  So on Cloud Run there is no "neither" case: pass one has to
#  name an audience, and the only honest thing to name before the URL exists is
#  a value no Google-signed token can ever carry.
#
#  The placeholder is therefore not a weakening.  A revision running under it
#  verifies every inbound token against an audience nothing was minted for and
#  refuses all of them, which is the same posture as refusing to start and is
#  strictly more useful: it produces the URL pass two needs.  Pass two replaces
#  it with the service's own URL, and no invoker binding exists until
#  60-invoker.sh runs, so the placeholder revision is closed twice over.
#
#  Idempotent: re-running redeploys the same configuration.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

#  ---- preflight: does this model answer, where this deployment calls it? ----
#
#  Gemini availability is per location and moves.  A model that is not served in
#  VERTEX_LOCATION does not fail loudly at deploy time: the revision comes up,
#  every interpretation raises inside the model client, and the runtime turns
#  that into ``INTERPRETER_UNAVAILABLE`` -- an honest abstention, per assignment,
#  forever.  The whole fleet then looks exactly like a set of sources with
#  nothing to say, which is the failure mode the agent's own composition root
#  refuses to start rather than produce.
#
#  So it is checked here, against the live API, before anything is deployed.
#
#  **What is asked is the question the agent will ask.**  This check used to read
#  the publisher model as a resource -- a plain GET of
#  ``.../publishers/google/models/${AGENT_MODEL}`` -- and that read is not a test
#  of publisher Gemini availability.  It answers 404 for models that serve
#  requests perfectly well in the same project and the same location, which was
#  confirmed by hand here: ``gemini-3.5-flash`` in ``asia-south1`` answers 404 to
#  the metadata read and 200 to ``:countTokens``.  The pair that ships now --
#  ``gemini-3.7-flash`` at ``global`` -- was verified the same way against this
#  project and answers 200 to ``:countTokens``.  A preflight that refuses where
#  the deployment would have worked is worse than no preflight, because of what
#  it makes somebody do next: change the model, or move VERTEX_LOCATION -- and
#  moving VERTEX_LOCATION moves where the interpretation happens, which is a
#  data-flow decision taken for a reason that was not true.
#
#  **VERTEX_LOCATION is not REGION, and this check reads only the former.**  The
#  Cloud Run region and the evidence bucket are REGION and stay there; what is
#  probed here is the inference endpoint the revision is handed as
#  GOOGLE_CLOUD_LOCATION, which ships as ``global``.  A check that fell back to
#  REGION would report on a location no model call is ever made at.
#
#  **``:countTokens`` and not ``:generateContent``.**  It is served by the same
#  publisher model at the same location and reached over the same path, so it
#  answers the availability question the same way -- and it produces no
#  completion.  No tokens are generated, no inference quota is spent, and nothing
#  is billed for asking whether a deployment is ready.  A readiness probe that
#  consumed a real inference request would charge a question about configuration
#  to the budget and the rate limit of the work.
#
#  Fails closed on everything that is not a count: 401, 403, 404, any other
#  non-2xx, an endpoint that cannot be reached at all, and a 200 whose body is
#  not a count -- because a 200 from something that is not Vertex says nothing
#  about Vertex.
#
#  Set SKIP_MODEL_CHECK=1 to proceed anyway -- for a model an operator knows is
#  served and this probe cannot reach.  It is an override and not a default,
#  because the thing it overrides is the one misconfiguration that produces no
#  error anywhere.
muster::check_model() {
  if [[ "${SKIP_MODEL_CHECK:-0}" == "1" ]]; then
    echo "  SKIPPED  SKIP_MODEL_CHECK=1; ${AGENT_MODEL} in ${VERTEX_LOCATION} is unverified"
    return
  fi

  local host url token payload answer status body diagnosis
  #  ``global`` is not a regional prefix: the global endpoint is the bare host,
  #  and ``global-aiplatform.googleapis.com`` resolves to nothing -- which would
  #  make this check report "not served" for the one location several current
  #  Gemini models are served in, and send an operator to change a model that
  #  was right.
  if [[ "${VERTEX_LOCATION}" == "global" ]]; then
    host="aiplatform.googleapis.com"
  else
    host="${VERTEX_LOCATION}-aiplatform.googleapis.com"
  fi
  url="https://${host}/v1/projects/${PROJECT_ID}/locations/${VERTEX_LOCATION}"
  url="${url}/publishers/google/models/${AGENT_MODEL}:countTokens"

  #  The smallest thing that is still a request the model has to read.  A literal
  #  here, and never anything from the case: a preflight has no evidence in
  #  scope, and writing the probe into the file is what keeps it that way when
  #  somebody later wants a "more realistic" one.
  payload='{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}'

  token="$(gcloud auth print-access-token 2>/dev/null || true)"
  if [[ -z "${token}" ]]; then
    {
      echo
      echo "  FAIL  no access token for the Vertex AI API."
      echo "        Authenticate and run this again:  gcloud auth login"
      echo
      echo "        Nothing has been deployed."
      echo
    } >&2
    exit 1
  fi

  #  The token goes in through a config file on stdin rather than on the command
  #  line: an argument is visible in the process table to every other user on the
  #  machine, and lands in shell history and in anything written under ``set -x``.
  #  The status code is appended on a line of its own, so one call yields both it
  #  and the body -- and the body is what separates a count from a 200 that is
  #  not one.
  answer="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" \
    | curl --config - \
        --silent --show-error \
        --write-out '\n%{http_code}' \
        -X POST "${url}" \
        -H "Content-Type: application/json" \
        --data "${payload}" || true)"
  status="${answer##*$'\n'}"
  body="${answer%$'\n'*}"
  [[ -n "${status}" ]] || status="000"

  if [[ "${status}" == "200" ]]; then
    #  A count, and not merely an answer.  A proxy, a captive portal or a
    #  misrouted host can all return 200; none of them returns the field the
    #  response type is defined by.  If Google ever renames it, this refuses
    #  loudly with the body printed below, which is the direction to fail in.
    if [[ "${body}" == *'"totalTokens"'* ]]; then
      echo "  PASS  ${AGENT_MODEL} counted tokens in ${VERTEX_LOCATION}"
      return
    fi
    diagnosis="the endpoint answered 200 with something that is not a token count."
  else
    case "${status}" in
      401) diagnosis="the credentials were refused; the token is missing, expired or wrong." ;;
      403) diagnosis="the caller may not call Vertex AI here, or the API is not enabled." ;;
      404) diagnosis="the model is not served at this location." ;;
      000) diagnosis="the endpoint could not be reached at all (DNS, proxy or network)." ;;
      *) diagnosis="the endpoint answered something this check will not read as a yes." ;;
    esac
  fi

  {
    echo
    echo "  FAIL  ${AGENT_MODEL} did not answer :countTokens in ${VERTEX_LOCATION} (HTTP ${status})."
    echo "        ${diagnosis}"
    echo
    echo "        Nothing has been deployed."
    echo
    case "${status}" in
      401)
        echo "        Authenticate and run this again:"
        echo
        echo "            gcloud auth login"
        echo "            ./infra/scripts/50-deploy.sh"
        echo
        ;;
      403)
        echo "        Two things answer 403, and they are different repairs:"
        echo
        echo "        1. The API is off in this project.  00-enable-apis.sh turns it"
        echo "           on, and is safe to re-run:"
        echo
        echo "               ./infra/scripts/00-enable-apis.sh"
        echo
        echo "        2. This principal may not call Vertex AI.  The deployed agents"
        echo "           hold roles/aiplatform.user; the account running this script"
        echo "           needs it too, for the length of this check."
        echo
        ;;
      404)
        echo "        Two ways forward, and they are not the same decision:"
        echo
        echo "        1. Name a model served in ${VERTEX_LOCATION}.  Where the model"
        echo "           is called does not move, so neither does the answer to"
        echo "           'what leaves ${REGION}':"
        echo
        echo "               AGENT_MODEL=<a model served there> ./infra/scripts/50-deploy.sh"
        echo
        echo "        2. Call this model where it is served.  The site's stored"
        echo "           objects still never move -- they stay in the bucket in"
        echo "           ${REGION}, read by the source agent alone; what crosses"
        echo "           is the source agent's own interpreter call, carrying the"
        echo "           evidence content it needs interpreted.  But the"
        echo "           interpretation then happens wherever this names, and that"
        echo "           is a data-flow to state out loud rather than inherit:"
        echo
        echo "               VERTEX_LOCATION=<where it is served> ./infra/scripts/50-deploy.sh"
        echo
        echo "           VERTEX_LOCATION=${REGION} is the co-located choice, and is"
        echo "           correct for any model served regionally there.  It is not"
        echo "           the shipped default, because the shipped model is not."
        echo
        echo "        Model availability is per location and changes; check the"
        echo "        published Vertex AI model-locations table before choosing."
        echo
        ;;
    esac
    echo "        What the endpoint answered:"
    printf '%s' "${body}" | tr '\n' ' ' | cut -c 1-400 | sed 's/^/          /'
    echo
  } >&2
  exit 1
}

#  Before anything reaches the network.  This is the one precondition that
#  costs no API call, and it gates the value this script is about to mount as
#  the source signing key -- checking it after the model preflight and pass one
#  would mean discovering it with half a fleet already up.
muster::banner "preflight: is SIGNING_KEY_VERSION pinned?"
muster::require_signing_key_version
echo "  SIGNING_KEY_VERSION=${SIGNING_KEY_VERSION}, pinned"

muster::banner "preflight: does ${AGENT_MODEL} answer in ${VERTEX_LOCATION}?"
muster::check_model

muster::deploy() {
  local service="$1" account="$2" agent_id="$3" principal="$4" source_class="$5"
  local key_ref="$6" predicates="$7" scope="$8" prefix="$9" secret="${10}"
  local audience="${11:-}"

  #  Written to a file rather than packed into one delimited argument.  Several
  #  of these values contain the characters a delimiter would have to be:
  #  MUSTER_AGENT_PREDICATES is a comma-separated list, MUSTER_AGENT_RESOURCE_SCOPE
  #  carries a colon, MUSTER_AGENT_AUDIENCE is a URL, and
  #  MUSTER_AGENT_PERMITTED_CALLERS is a service-account address containing an
  #  '@'.  See muster::env_entry in env.sh for the two deploys that discovered
  #  this the hard way.  Both passes go through here, so the placeholder audience
  #  and the resolved one are serialised identically.
  local env_file
  muster::env_file "${service}"
  env_file="${MUSTER_ENV_FILE}"
  {
    muster::env_entry MUSTER_AGENT_ID "${agent_id}"
    muster::env_entry MUSTER_AGENT_PRINCIPAL "${principal}"
    muster::env_entry MUSTER_AGENT_TENANT "${TENANT_ID}"
    muster::env_entry MUSTER_AGENT_SOURCE_CLASS "${source_class}"
    muster::env_entry MUSTER_AGENT_KEY_REF "${key_ref}"
    muster::env_entry MUSTER_AGENT_SIGNING_KEY_PATH "${SIGNING_KEY_MOUNT}"
    muster::env_entry MUSTER_AGENT_PREDICATES "${predicates}"
    muster::env_entry MUSTER_AGENT_RESOURCE_SCOPE "${scope}"
    muster::env_entry MUSTER_AGENT_MATERIAL_BUCKET "${EVIDENCE_BUCKET}"
    muster::env_entry MUSTER_AGENT_MATERIAL_PREFIX "${prefix}"
    muster::env_entry MUSTER_AGENT_MODEL_BACKEND "VERTEX"
    muster::env_entry MUSTER_AGENT_MODEL "${AGENT_MODEL}"
    muster::env_entry GOOGLE_CLOUD_PROJECT "${PROJECT_ID}"
    muster::env_entry GOOGLE_CLOUD_LOCATION "${VERTEX_LOCATION}"
    #  Always both, never neither.  See the header: a Cloud Run revision that
    #  names no audience refuses to start, so pass one names the placeholder and
    #  pass two names the service's own URL.
    muster::env_entry MUSTER_AGENT_AUDIENCE "${audience:-${UNRESOLVED_AUDIENCE}}"
    muster::env_entry MUSTER_AGENT_PERMITTED_CALLERS "${CONTROL_PLANE_SA}"
  } > "${env_file}"

  gcloud run deploy "${service}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE}" \
    --service-account="${account}" \
    --no-allow-unauthenticated \
    --ingress="${RUN_INGRESS}" \
    --cpu="${RUN_CPU}" \
    --memory="${RUN_MEMORY}" \
    --timeout="${RUN_TIMEOUT}" \
    --max-instances="${RUN_MAX_INSTANCES}" \
    --set-secrets="${SIGNING_KEY_MOUNT}=${secret}:${SIGNING_KEY_VERSION}" \
    --env-vars-file="${env_file}" \
    --quiet
}

muster::url_of() {
  gcloud run services describe "$1" \
    --project="${PROJECT_ID}" --region="${REGION}" --format="value(status.url)"
}

muster::banner "pass 1: deploy with a placeholder audience (${UNRESOLVED_AUDIENCE})"
muster::deploy "${SITE_SERVICE}" "${SITE_SA}" \
  "${SITE_AGENT_ID}" "${SITE_PRINCIPAL}" "SITE_ACCESS_CONTROL" "${SITE_KEY_REF}" \
  "present_on_site,on_site_duration" "SITE:${SITE_PRINCIPAL}" "${SITE_PREFIX}" \
  "${SITE_SECRET}"
muster::deploy "${EMPLOYER_SERVICE}" "${EMPLOYER_SA}" \
  "${EMPLOYER_AGENT_ID}" "${EMPLOYER_PRINCIPAL}" "HR_PAYROLL_SYSTEM" "${EMPLOYER_KEY_REF}" \
  "daily_rate,scheduled" "EMPLOYER:${EMPLOYER_PRINCIPAL}" "${EMPLOYER_PREFIX}" \
  "${EMPLOYER_SECRET}"

SITE_URL="$(muster::url_of "${SITE_SERVICE}")"
EMPLOYER_URL="$(muster::url_of "${EMPLOYER_SERVICE}")"

muster::banner "pass 2: tell each service its own audience"
muster::deploy "${SITE_SERVICE}" "${SITE_SA}" \
  "${SITE_AGENT_ID}" "${SITE_PRINCIPAL}" "SITE_ACCESS_CONTROL" "${SITE_KEY_REF}" \
  "present_on_site,on_site_duration" "SITE:${SITE_PRINCIPAL}" "${SITE_PREFIX}" \
  "${SITE_SECRET}" "${SITE_URL}"
muster::deploy "${EMPLOYER_SERVICE}" "${EMPLOYER_SA}" \
  "${EMPLOYER_AGENT_ID}" "${EMPLOYER_PRINCIPAL}" "HR_PAYROLL_SYSTEM" "${EMPLOYER_KEY_REF}" \
  "daily_rate,scheduled" "EMPLOYER:${EMPLOYER_PRINCIPAL}" "${EMPLOYER_PREFIX}" \
  "${EMPLOYER_SECRET}" "${EMPLOYER_URL}"

cat <<SUMMARY

  ${SITE_SERVICE}      ${SITE_URL}
  ${EMPLOYER_SERVICE}  ${EMPLOYER_URL}

  Cloud Run and the evidence bucket : ${REGION}
  Vertex Gemini (${AGENT_MODEL})    : ${VERTEX_LOCATION}

  Two locations, deliberately.  The site's material stays in ${REGION} and is
  read only by the source agent's own identity; what reaches ${VERTEX_LOCATION}
  is a prompt the agent built from it, and never the material.

  Publish these as the endpoint_ref of the matching profiles in the tenant's
  fleet catalog.  A catalog is a signed control-plane publication: an agent
  cannot enter itself into one, which is why this script prints the URLs
  instead of registering them.

SUMMARY
