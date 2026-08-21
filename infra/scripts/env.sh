#!/usr/bin/env bash
#  One place every name in the deployment comes from.  Sourced by every other
#  script here, and by nothing that runs in production: a deployed service reads
#  its own environment, and a script that could change what a running service
#  believes about itself would be a second source of truth for its identity.
#
#  Every value is overridable from the environment, so a second project, a
#  second region or a personal sandbox needs no edit to this file.
set -euo pipefail

: "${PROJECT_ID:=$(gcloud config get-value project 2>/dev/null || true)}"
if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "PROJECT_ID is not set and gcloud has no configured project." >&2
  echo "Set it explicitly:  PROJECT_ID=my-project ./infra/scripts/00-enable-apis.sh" >&2
  exit 2
fi

#  ---- where things run ----------------------------------------------------
#
#  REGION is where the Cloud Run services execute and where the private
#  evidence bucket lives.  They are deliberately the same: the site's raw
#  material and the process that reads it should not be in two jurisdictions
#  because nobody chose.
: "${REGION:=asia-south1}"

#  VERTEX_LOCATION is where the *model* is called, and only that.  A separate
#  value from REGION, never derived from it: they are two decisions, and a
#  default that made one follow the other is what let a change to either move
#  both without anybody saying so.
#
#  **It ships as ``global``, and that is a stated data-flow rather than an
#  oversight.**  AGENT_MODEL below is served from the global Vertex endpoint --
#  confirmed against the live API in this project, by :countTokens, which is the
#  API the agent itself calls.  So the *interpretation* happens outside the
#  region the material sits in.
#
#  What that does and does not mean:
#
#    * the site's material never moves.  The objects stay in EVIDENCE_BUCKET, in
#      REGION, and are read only by the source agent's own identity -- see
#      20-site-evidence.sh, and 70-verify-iam.sh, which asserts that the control
#      plane cannot read them.  Nothing copies them anywhere.
#    * what crosses is a prompt built from that material, by the source agent,
#      inside its own container.  That is a smaller thing than moving the
#      evidence and it is not a nothing, which is why it is written down here
#      instead of being inherited from a default.
#
#  Setting VERTEX_LOCATION=${REGION} restores full co-location, and is correct
#  for any model served regionally in REGION.  50-deploy.sh re-checks the
#  model/location pair against the live API before anything is deployed --
#  specifically not by reading the model as a resource, which answers 404 for
#  models that serve requests perfectly well there.  See 50-deploy.sh and
#  infra/README.md.
: "${VERTEX_LOCATION:=global}"

#  ---- names ---------------------------------------------------------------
: "${EVIDENCE_BUCKET:=muster-site-evidence-${PROJECT_ID}}"
: "${SITE_PREFIX:=site-a}"
: "${EMPLOYER_PREFIX:=employer-1}"

: "${REPO:=muster}"
: "${IMAGE_TAG:=latest}"
: "${IMAGE:=${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/muster-agent:${IMAGE_TAG}}"

#  **A second image, and the split is the point of it.**  The agent image
#  installs a model client and an agent framework; the control-plane image
#  installs neither and cannot -- so "the process holding the case record has no
#  model dependency" is a fact about what is in the container rather than a rule
#  somebody has to keep remembering.  Built from the same context in the same
#  submission, so the two cannot drift apart by a tag.
: "${CONTROL_PLANE_IMAGE:=${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/muster-control-plane:${IMAGE_TAG}}"

#  A build identity of its own.  Without one, ``gcloud builds submit`` runs
#  as the project's default build or compute service account -- and the
#  compute default carries ``roles/editor`` unless an organisation policy
#  says otherwise, which includes project-wide object reads.  Anybody who
#  can start a build could then cat the site's material, around every
#  binding 20-site-evidence.sh so carefully narrows.
: "${BUILD_SA_ID:=muster-build}"
: "${CONTROL_PLANE_SA_ID:=muster-control-plane}"
: "${SITE_SA_ID:=muster-site-agent}"
: "${EMPLOYER_SA_ID:=muster-employer-agent}"

BUILD_SA="${BUILD_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"
CONTROL_PLANE_SA="${CONTROL_PLANE_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"
SITE_SA="${SITE_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"
EMPLOYER_SA="${EMPLOYER_SA_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

#  The control plane runs *inside the project* as a Cloud Run job, under its
#  own identity.  That is what makes the denial 70-verify-iam.sh records a
#  fact about a running process rather than about an account nothing
#  executes as.
: "${PROBE_JOB:=muster-control-plane-probe}"
#  The worked run, as a second job under the same identity.  A **job** and not
#  a service, deliberately: the control plane here calls outbound and is never
#  called, so a service would be an ingress nothing needs and one more thing to
#  hold closed.  It runs once, to completion, and leaves nothing listening.
: "${HERO_JOB:=muster-control-plane-hero}"
: "${SITE_SERVICE:=muster-site-agent}"
: "${EMPLOYER_SERVICE:=muster-employer-agent}"

#  ---- how the hero job reaches the agents ---------------------------------
#
#  **Direct VPC egress, by default, and not as a remedy.**  A Cloud Run resource
#  calling a service that is ``--ingress=internal`` is recognised as internal
#  traffic only when its request is routed through a VPC network in the project.
#  Default job networking is not that route, so a hero job left on it would be
#  judged at the agent's perimeter and refused before the agent ever saw the
#  assignment -- a 403 from Cloud Run that looks nothing like an authorization
#  decision and reads, to anybody watching the demo, like the fleet is down.
#
#  So the network is named here rather than discovered by an operator reading a
#  failure.  ``default``/``default`` is the auto-mode network and the regional
#  subnet every new project has; a project that deleted them, or that keeps its
#  workloads on a named network, overrides these two and nothing else.
#  Assigned with ``=`` rather than ``:=``, which is the only place in this file
#  that matters: for these two, *empty* is a meaningful value -- it means "no
#  network", which is the diagnostic path 90-hero-job.sh takes and warns about.
#  Under ``:=`` an operator who exported an empty one would silently get the
#  default back, and the branch below could never be reached deliberately.
: "${HERO_VPC_NETWORK=default}"
: "${HERO_VPC_SUBNET=default}"

#  ``all-traffic`` and not ``private-ranges-only``, because the destination is
#  the agent's ordinary ``run.app`` URL -- a public hostname resolving to a
#  public address.  Under ``private-ranges-only`` that request would leave by the
#  default path, arrive from outside any VPC, and be judged at the perimeter
#  exactly as if no network had been named at all: the configuration would look
#  right and do nothing.  Sending all of it through the VPC is what makes the
#  origin unambiguous, and it is the whole reason to attach a network here.
: "${HERO_VPC_EGRESS:=all-traffic}"

: "${SITE_SECRET:=muster-site-signing-key}"
: "${EMPLOYER_SECRET:=muster-employer-signing-key}"

#  The audience the first deploy pass names, before the service has a URL.
#
#  A Cloud Run revision that names no audience refuses to start -- deliberately,
#  because such a revision would accept an assignment from anybody who could
#  reach it -- so the first pass cannot simply omit it.  What it names instead
#  is a value no Google-signed identity token can ever carry, so the revision
#  comes up, verifies every inbound token against it, and refuses every one.
#  ``.invalid`` is reserved by RFC 2606 and resolves nowhere, which is what
#  makes this unmistakable in a configuration listing rather than merely wrong.
: "${UNRESOLVED_AUDIENCE:=https://audience-not-yet-resolved.invalid}"

#  Where each service's signing key is mounted inside its container.  The same
#  string goes into MUSTER_AGENT_SIGNING_KEY_PATH, so the mount and the process
#  cannot disagree about where the key is.
: "${SIGNING_KEY_MOUNT:=/var/run/muster/signing-key.pem}"

#  Which secret version each agent mounts.  **Pinned, not ``latest``.**
#  A key reference is a fixed string in the authority registry, and
#  ``latest`` resolves at every cold start -- so adding a version would
#  rotate the key that signs while leaving unchanged the key reference the
#  receipt claims signed it.  Check Q-12(b) then refuses, on a subset of
#  instances, hours later, and the observable is "the site's key is
#  compromised".  30-secrets.sh prints the version it wrote; set it here.
#
#  **There is no default, and ``latest`` is refused.**  A default here would be
#  that decision taken silently by this file; ``latest`` would be it taken
#  silently by Secret Manager, at every cold start.  Unset, empty, ``latest``
#  and anything that is not a positive decimal version number all stop the
#  deployment, at the point the key is mounted -- see
#  muster::require_signing_key_version below and its one caller in 50-deploy.sh.
: "${SIGNING_KEY_VERSION:=}"

#  Fail closed on the mount.  Not called at source time: every script here
#  sources this file, including 30-secrets.sh, which is what *prints* the
#  version there is to pin -- a check that ran on sourcing would refuse to mint
#  the key whose version it is demanding.  So the guard sits where the value is
#  actually used, and the scripts that run before a key exists are unaffected.
muster::require_signing_key_version() {
  local version="${SIGNING_KEY_VERSION:-}"
  if [[ "${version}" =~ ^[1-9][0-9]*$ ]]; then
    return 0
  fi
  {
    if [[ -z "${version}" ]]; then
      echo "SIGNING_KEY_VERSION is not set, and there is no default."
    else
      echo "SIGNING_KEY_VERSION is '${version}', which is not a pinned version."
    fi
    echo
    echo "  It must be the Secret Manager version number 30-secrets.sh printed:"
    echo "  a positive decimal integer.  'latest' is refused deliberately -- it"
    echo "  resolves at every cold start, so a later 30-secrets.sh run would"
    echo "  rotate the key that signs while MUSTER_AGENT_KEY_REF, the reference"
    echo "  the receipt claims signed it, stayed as it was.  Check Q-12(b) would"
    echo "  then refuse receipts on whichever instances had restarted since."
    echo
    echo "  Both secrets must be at the same version, or deploy one service at a"
    echo "  time.  Set it explicitly:"
    echo
    echo "      export SIGNING_KEY_VERSION=3"
    echo
  } >&2
  exit 2
}

#  ---- what the agents are -------------------------------------------------
#
#  These must match the authority registry and the fleet catalog the control
#  plane publishes.  An agent configured with a key the registry does not grant
#  produces receipts that check Q-12(b) refuses -- correct behaviour, and a
#  confusing way to discover a typo here.
: "${TENANT_ID:=ALPHA}"
: "${SITE_AGENT_ID:=agent-site-a}"
: "${SITE_PRINCIPAL:=SITE-A}"
: "${EMPLOYER_AGENT_ID:=agent-hr-payroll}"
: "${EMPLOYER_PRINCIPAL:=EMPLOYER-1}"

#  **A deployed key is a different key, so it carries a different reference.**
#  The worked case's historical record is seeded under ``key-site-a-1`` and
#  ``key-hr-payroll-1``, whose private halves belong to whoever seeded it.  The
#  keys 30-secrets.sh mints and mounts here are new ones, held only by the
#  agents -- and a verifier resolves one public key per reference, so reusing
#  the seeded references would mean the registry could hold the seed's public
#  key or the deployment's and not both.  Two keys, two references: that is
#  exactly what Q-12(b) compares, and collapsing them is how a key rotation
#  becomes an outage that reads as a compromise.
: "${SITE_KEY_REF:=key-site-a-cloud-1}"
: "${EMPLOYER_KEY_REF:=key-hr-payroll-cloud-1}"

#  The model, chosen together with VERTEX_LOCATION above and never separately.
#  This one is served from the ``global`` Vertex endpoint, which is why
#  VERTEX_LOCATION ships as ``global`` and not as ${REGION}; the pair was
#  verified by hand in this project -- gemini-3.7-flash at global answered
#  :countTokens with HTTP 200.  50-deploy.sh re-checks the pair against the live
#  API -- with ``:countTokens``, the API the agent itself calls -- before it
#  deploys anything, because availability moves.
#
#  Overriding one without the other is the mistake this pairing exists to make
#  visible: a model served only globally, deployed with a regional
#  VERTEX_LOCATION, produces a fleet that comes up and abstains forever.
: "${AGENT_MODEL:=gemini-3.7-flash}"

#  ---- Cloud Run shape -----------------------------------------------------
: "${RUN_CPU:=1}"
: "${RUN_MEMORY:=1Gi}"
#  The request bound, and it has to cover a **cold start plus a model turn**.
#  Cloud Run starts counting when the request arrives, so the first assignment
#  after a scale to zero pays for the image pull, the interpreter import and the
#  model client's own start-up before a single token is produced -- and only
#  then does the agent's 45-second interpreter budget begin.  A bound covering
#  the budget alone would cut the first request of every demo, which is the one
#  anybody watches.  The control plane waits longer than this; see
#  ``HttpAcquisitionTransport``.
: "${RUN_TIMEOUT:=180}"
: "${RUN_MAX_INSTANCES:=2}"
#  An agent serves one machine caller.  ``internal`` refuses anything that did
#  not originate inside a VPC network in this project, which is a network
#  control *in addition* to the IAM invoker binding and the in-app identity
#  check.  The hero job satisfies it by routing its egress through the VPC --
#  see HERO_VPC_NETWORK above -- so this stays ``internal`` on the normal path
#  and there is no supported deployment in which it does not.
#
#  ``RUN_INGRESS=all`` is a **diagnostic escape hatch and not a configuration**:
#  a way to establish, for one run, whether a failure is the network perimeter
#  or something above it.  It removes the outermost of three controls, leaving
#  the invoker binding and the agent's own caller allowlist as the only things
#  between the open internet and the port.  Set it back before anybody relies on
#  the result.
: "${RUN_INGRESS:=internal}"

#  ---- the worked case, as the hero job runs it ----------------------------
#
#  The case identifier is a label rather than a key here, because the hero job's
#  store is in-memory and lives as long as the execution does.  It is named
#  anyway: it appears inside every signed payload the run produces, so a second
#  run under a second name is a genuinely different set of receipts.
: "${HERO_CASE_ID:=CASE-RAVI-SAT-CLOUD}"

#  The object the hero job attempts to read directly, under the control plane's
#  own identity, and must be refused.  The same object 70-verify-iam.sh asserts
#  about, so the policy check and the running process say the same thing about
#  the same thing.
: "${HERO_RAW_OBJECT:=${SITE_PREFIX}/gate-log-sat.txt}"

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES="${REPOSITORY_ROOT}/packages/muster-agents/fixtures"
EVIDENCE_DIR="${REPOSITORY_ROOT}/infra/evidence"

export PROJECT_ID REGION VERTEX_LOCATION EVIDENCE_BUCKET SITE_PREFIX EMPLOYER_PREFIX
export REPO IMAGE IMAGE_TAG CONTROL_PLANE_IMAGE
export CONTROL_PLANE_SA SITE_SA EMPLOYER_SA BUILD_SA
export CONTROL_PLANE_SA_ID SITE_SA_ID EMPLOYER_SA_ID BUILD_SA_ID
export SITE_SERVICE EMPLOYER_SERVICE SITE_SECRET EMPLOYER_SECRET PROBE_JOB HERO_JOB
export HERO_VPC_NETWORK HERO_VPC_SUBNET HERO_VPC_EGRESS HERO_CASE_ID HERO_RAW_OBJECT
export SIGNING_KEY_MOUNT SIGNING_KEY_VERSION UNRESOLVED_AUDIENCE
export TENANT_ID SITE_AGENT_ID SITE_PRINCIPAL SITE_KEY_REF
export EMPLOYER_AGENT_ID EMPLOYER_PRINCIPAL EMPLOYER_KEY_REF AGENT_MODEL
export RUN_CPU RUN_MEMORY RUN_TIMEOUT RUN_MAX_INSTANCES RUN_INGRESS
export REPOSITORY_ROOT FIXTURES EVIDENCE_DIR

#  ---- how a Cloud Run resource is told what it is -------------------------
#
#  **Written to a file, not argued on the command line.**  ``--set-env-vars``
#  takes one string holding every name and every value, split on a delimiter --
#  and a delimiter has to be a character that appears in no value.  This
#  deployment has now twice chosen one that does.
#
#  The first was the comma, which is the default.  MUSTER_AGENT_PREDICATES is
#  itself a comma-separated list, so its second predicate parsed as an entry
#  with no ``=`` and the deploy aborted.  The repair was gcloud's alternate
#  delimiter syntax, ``^@^`` -- and the second discovery is that
#  MUSTER_AGENT_PERMITTED_CALLERS is a service-account address:
#
#      muster-control-plane@PROJECT.iam.gserviceaccount.com
#
#  which split at its own ``@``, leaving the tail to be reported as a malformed
#  entry naming something nobody typed.
#
#  There is no third character to pick.  A value here is a list, an address, a
#  URL, a path or base64, and choosing a delimiter is a bet that no future value
#  contains it.  Both bets lost, both at deploy time, and both looked like a
#  syntax error rather than like the design fault they were.  A file has no
#  delimiter: one entry per line, and the value quoted.
#
#  Single-quoted YAML scalars, with any embedded quote doubled -- the one escape
#  a single-quoted scalar has, and the reason to use them: everything else is
#  literal, so a comma, an ``@``, a ``:``, a ``/``, a ``#`` or an ``=`` is value
#  bytes and cannot be read as structure.  Quoting also keeps ``true`` a string
#  rather than a boolean, and ``01`` a string rather than the number 1.
#
#  Two things this deliberately is not.  It is not how a secret travels: the
#  signing key reaches a container through ``--set-secrets``, as a reference to a
#  Secret Manager version, so no private key is written here or passed to
#  anything.  And it is not a vault -- 0700 under the system temp directory and
#  removed on exit is right for configuration and is not a place to put a value
#  that must not be read.
muster::env_entry() {
  local name="$1" value="$2"
  #  One entry, one line.  A newline in a value would be a second line that
  #  is not an entry -- and a single-quoted YAML scalar folds one into a
  #  space rather than refusing, so the container would come up holding a
  #  value that is nearly the one it was given.  Nothing here sends one;
  #  this is what makes that a property rather than an observation about
  #  today's values.
  if [[ "${value}" == *$'\n'* ]]; then
    echo "  ${name} holds a newline, which a Cloud Run environment cannot carry" >&2
    exit 2
  fi
  printf "%s: '%s'\n" "${name}" "${value//\'/\'\'}"
}

#: Where those files are written, created on first use.  Assigned rather than
#: defaulted from the environment, deliberately: this is the path that gets
#: removed, and an inherited one would be somebody else's directory.
MUSTER_ENV_DIR=""

#: Where muster::env_file leaves its answer.  See the note there for why that is
#: a variable rather than something printed.
MUSTER_ENV_FILE=""

muster::env_cleanup() {
  if [[ -n "${MUSTER_ENV_DIR}" && -d "${MUSTER_ENV_DIR}" ]]; then
    rm -rf "${MUSTER_ENV_DIR}"
  fi
  MUSTER_ENV_DIR=""
  MUSTER_ENV_FILE=""
  return 0
}

#  A path to write one resource's environment to, left in MUSTER_ENV_FILE.  The
#  directory is made once, by mktemp -- 0700, outside the repository, under an
#  unpredictable name -- and the traps remove it however the script ends:
#  normally, on a refusal that exits early, and on the interrupt somebody types
#  when a deploy hangs.
#
#  **It cannot print its answer, and that is not a style choice.**  A caller
#  would read a printed path through ``$(...)``, which is a subshell: the
#  directory would be created there, this function's own EXIT trap would fire as
#  that subshell ended, and the path handed back would name a directory that had
#  already been removed.  The deploy then fails on a redirect to a file in a
#  directory that does not exist -- naming a path that was real when it was
#  printed, which is the least legible way this could go wrong.
muster::env_file() {
  if [[ -z "${MUSTER_ENV_DIR}" ]]; then
    MUSTER_ENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/muster-env.XXXXXX")"
    trap muster::env_cleanup EXIT
    trap 'muster::env_cleanup; exit 130' INT
    trap 'muster::env_cleanup; exit 143' TERM
  fi
  MUSTER_ENV_FILE="${MUSTER_ENV_DIR}/$1.yaml"
}

muster::banner() {
  echo
  echo "== $* =="
}

#  ---- running a job, and reading back exactly what that run printed -------
#
#  **A job outlives its executions, and its logs outlive them too.**  That is
#  what made the previous evidence collection wrong, and wrong in the one
#  direction that matters: 90-hero-job.sh read
#
#      resource.type=cloud_run_job AND resource.labels.job_name=${HERO_JOB}
#      --limit=200 --order=asc
#
#  which is a filter over the *job*, not over the run that had just happened.
#  ``--order=asc`` sorts oldest first and ``--limit`` then keeps the first 200 --
#  so what came back was the **earliest** 200 lines the job had ever produced,
#  from whichever execution happened to be first.  A successful run whose
#  predecessor had timed out therefore printed, under the heading "what it
#  printed":
#
#      Terminating task because it has reached the maximum timeout of 900 seconds.
#
#  -- a line belonging to a different execution, presented as this one's output.
#  There is no worse failure available to an evidence path than a real line from
#  the wrong run, because everything about it is authentic except what it is
#  evidence of.  And it gets worse with age rather than better: once a job has
#  200 entries behind it the current execution's output can never appear at all,
#  and the heading above it stays exactly the same.
#
#  So an execution is identified **by the call that created it**, and every read
#  is scoped to that identifier.  Not "the most recent execution", which is a
#  guess that is usually right -- a retry, or a second operator, and it is a
#  guess that is quietly wrong.  ``--async`` returns the created execution's name
#  immediately and unconditionally, including for a run that will go on to fail,
#  which is precisely the run whose output somebody needs to read.  The wait is
#  then ours to do, against that one name.

#: How long muster::execute_job waits for an execution to complete, and how
#: often it asks.  The bound covers the job's own --task-timeout with room for
#: the image pull and the scheduling ahead of it; an execution still running
#: when it expires is reported as undetermined and never as a verdict.
: "${JOB_WAIT_SECONDS:=1200}"
: "${JOB_POLL_SECONDS:=10}"
export JOB_WAIT_SECONDS JOB_POLL_SECONDS

#: The execution muster::execute_job created, for the caller to read logs by.
#: Left set on failure as well as on success -- a failed run is the one whose
#: output is worth reading -- and cleared before every new execution, so a
#: caller can never scope a read to a name left over from a previous call.
MUSTER_EXECUTION=""

#  Start one job and wait for that execution, and only that one.
#
#      0  the execution completed and its task succeeded
#      1  the execution completed and its task failed
#      2  no execution was started, or its outcome could not be read
#
#  The third is separate on purpose.  "The run said no" and "we do not know what
#  the run said" are different facts, and collapsing them into one non-zero exit
#  is how an undetermined result gets reported as a verdict.
muster::execute_job() {
  local job="$1"
  MUSTER_EXECUTION=""

  #  Two fields, because the created execution's name sits at ``metadata.name``
  #  in gcloud's Knative-shaped representation of a Cloud Run execution and at
  #  ``name`` -- as a full resource path -- in the newer one.  Asking for both
  #  and taking whichever answered costs one projection and removes a dependency
  #  on which gcloud the operator happens to have.  It cannot be asked twice: a
  #  second execute is a second execution.
  local named=""
  named="$(gcloud run jobs execute "${job}" \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --async --format="value(metadata.name,name)")" || named=""

  local execution="${named%%$'\t'*}"
  if [[ -z "${execution}" ]]; then
    execution="${named#*$'\t'}"
  fi
  execution="${execution##*/}"

  if [[ -z "${execution}" ]]; then
    {
      echo "  ${job} was not started, or gcloud did not name the execution it created."
      echo "  Nothing is read back: an unnamed execution cannot be told from an older one."
    } >&2
    return 2
  fi

  MUSTER_EXECUTION="${execution}"
  echo "  execution ${execution}"

  local deadline=$(( SECONDS + JOB_WAIT_SECONDS ))
  local heartbeat=$(( SECONDS + 60 ))
  local completed=""
  while true; do
    #  ``status.completionTime`` is set when the execution stops, whichever way
    #  it stopped.  Polling for that rather than for a success condition is what
    #  keeps a failed run distinguishable from one still going.
    completed="$(gcloud run jobs executions describe "${execution}" \
      --project="${PROJECT_ID}" --region="${REGION}" \
      --format="value(status.completionTime)" 2>/dev/null)" || completed=""
    if [[ -n "${completed}" ]]; then
      break
    fi
    if (( SECONDS >= deadline )); then
      echo "  ${execution} had not completed after ${JOB_WAIT_SECONDS}s" >&2
      return 2
    fi
    if (( SECONDS >= heartbeat )); then
      echo "  still running: ${execution}"
      heartbeat=$(( SECONDS + 60 ))
    fi
    sleep "${JOB_POLL_SECONDS}"
  done

  local succeeded=""
  succeeded="$(gcloud run jobs executions describe "${execution}" \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --format="value(status.succeededCount)" 2>/dev/null)" || succeeded=""
  if [[ "${succeeded}" =~ ^[1-9][0-9]*$ ]]; then
    return 0
  fi
  return 1
}

#  Print what one execution printed.  Nothing else, and nothing at all when that
#  cannot be guaranteed.
#
#  ``labels."run.googleapis.com/execution_name"`` is the label Cloud Run stamps
#  on every entry a job execution produces -- the container's own output and the
#  platform's messages about that execution alike -- which is why the timeout
#  line that contaminated the previous reading is excluded by the same clause
#  that selects the output.  With the filter scoped, ``--limit`` bounds one
#  execution's output instead of silently truncating the job's whole history.
muster::execution_output() {
  local job="$1" execution="${2:-}"

  if [[ -z "${execution}" ]]; then
    {
      echo "  no execution was identified, so nothing here is certainly this run's output."
      echo "  A read scoped to the job alone would return an older execution's lines, which"
      echo "  is the failure this refuses rather than risks."
    } >&2
    return 1
  fi

  local filter="resource.type=\"cloud_run_job\""
  filter+=" AND resource.labels.job_name=\"${job}\""
  filter+=" AND labels.\"run.googleapis.com/execution_name\"=\"${execution}\""

  #  Ingestion is not instantaneous: an execution can be complete a moment
  #  before its last entries are queryable.  A bounded retry is the difference
  #  between "the run printed nothing" and "we asked too early", and those are
  #  not the same statement about a run.
  local attempt output=""
  for attempt in 1 2 3 4 5; do
    output="$(gcloud logging read "${filter}" \
      --project="${PROJECT_ID}" \
      --limit=1000 --order=asc --freshness=1d \
      --format="value(textPayload)")" || output=""
    if [[ -n "${output}" ]]; then
      break
    fi
    if (( attempt < 5 )); then
      sleep 3
    fi
  done

  if [[ -z "${output}" ]]; then
    {
      echo "  ${execution} has no readable log entries.  Nothing is printed, rather than"
      echo "  something belonging to another execution of ${job}."
    } >&2
    return 1
  fi

  printf '%s\n' "${output}"
  return 0
}

#  ---- the route's other half, which was a manual cloud prerequisite -------
#
#  Direct VPC egress with ``--vpc-egress=all-traffic`` sends *every* packet the
#  job emits through ${HERO_VPC_SUBNET}, and a Cloud Run instance on that route
#  has no external address.  The agents are reached at their ordinary
#  ``run.app`` hostnames, which resolve to Google front-end addresses -- so
#  unless the subnet has **Private Google Access**, those packets have no path
#  out and the job does not get an error.  It gets nothing: the outbound HTTPS
#  calls hang until the task timeout, and the execution ends with
#
#      Terminating task because it has reached the maximum timeout of 900 seconds.
#
#  which says nothing whatsoever about a subnet.  That is the failed execution
#  this deployment already produced, and the reason the next one worked was a
#  setting somebody turned on by hand -- a cloud prerequisite that existed
#  nowhere in these scripts and would have been missing again in the next
#  project, presenting as a fleet that is down.
#
#  So it is established here, explicitly, and refused precisely when it cannot
#  be.  **This broadens nothing.**  Private Google Access decides whether an
#  instance with no external address may reach Google APIs on the way *out*; it
#  grants no principal anything and it makes nothing reachable from outside the
#  project.  The agents stay ``--ingress=internal`` and their invoker bindings
#  are untouched -- this is what lets the job's request arrive at that perimeter
#  at all, not what gets it through.
#
#  Required only where the route needs it: under ``private-ranges-only`` a
#  ``run.app`` address is not a private range, so that request leaves by Cloud
#  Run's default path and Private Google Access has no bearing on it.  Demanding
#  it there would refuse a configuration that is merely differently broken.
muster::require_private_google_access() {
  if [[ -z "${HERO_VPC_NETWORK}" || -z "${HERO_VPC_SUBNET}" ]]; then
    return 0
  fi
  if [[ "${HERO_VPC_EGRESS}" != "all-traffic" ]]; then
    return 0
  fi

  local state=""
  state="$(gcloud compute networks subnets describe "${HERO_VPC_SUBNET}" \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --format="value(privateIpGoogleAccess)" 2>/dev/null)" || state=""

  if [[ -z "${state}" ]]; then
    {
      echo "  Subnet '${HERO_VPC_SUBNET}' was not readable in ${REGION} of ${PROJECT_ID}."
      echo
      echo "  The hero job routes all of its egress through that subnet, so it has to exist"
      echo "  and this deployment has to be able to read it.  Either it is not there -- a"
      echo "  project whose auto-mode network was deleted has no 'default' -- or the"
      echo "  identity running these scripts lacks compute.subnetworks.get."
      echo
      echo "      gcloud compute networks subnets list --project=${PROJECT_ID} \\"
      echo "        --filter=\"region:(${REGION})\""
      echo
      echo "  Name the one to use, and nothing else changes:"
      echo
      echo "      export HERO_VPC_NETWORK=your-network HERO_VPC_SUBNET=your-subnet"
      echo
    } >&2
    exit 2
  fi

  case "${state}" in
    True | true | TRUE)
      echo "  google    Private Google Access is on for ${HERO_VPC_SUBNET} in ${REGION}"
      return 0
      ;;
  esac

  echo "  google    Private Google Access is off for ${HERO_VPC_SUBNET} in ${REGION}; enabling it"
  if gcloud compute networks subnets update "${HERO_VPC_SUBNET}" \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --enable-private-ip-google-access --quiet; then
    state="$(gcloud compute networks subnets describe "${HERO_VPC_SUBNET}" \
      --project="${PROJECT_ID}" --region="${REGION}" \
      --format="value(privateIpGoogleAccess)" 2>/dev/null)" || state=""
    case "${state}" in
      True | true | TRUE)
        echo "  google    Private Google Access is now on for ${HERO_VPC_SUBNET} in ${REGION}"
        return 0
        ;;
    esac
  fi

  {
    echo "  Private Google Access is off for subnet '${HERO_VPC_SUBNET}' in ${REGION}, and"
    echo "  this deployment could not turn it on."
    echo
    echo "  Nothing has been deployed.  Refusing here is deliberate: the job would come up"
    echo "  looking entirely correct, reach nothing, and be killed by its own task timeout"
    echo "  with a message about 900 seconds and no mention of a network."
    echo
    echo "  Why it is needed.  The job carries --vpc-egress=${HERO_VPC_EGRESS}, so every"
    echo "  packet it emits leaves through this subnet, and a Cloud Run instance on that"
    echo "  route has no external address.  The agents answer at run.app hostnames on"
    echo "  Google front-end addresses; without Private Google Access those packets have"
    echo "  no path and the calls hang rather than fail."
    echo
    echo "  Enable it -- in the host project, if this is a Shared VPC:"
    echo
    echo "      gcloud compute networks subnets update ${HERO_VPC_SUBNET} \\"
    echo "        --project=${PROJECT_ID} --region=${REGION} \\"
    echo "        --enable-private-ip-google-access"
    echo
    echo "  It needs compute.subnetworks.setPrivateIpGoogleAccess, and it grants no"
    echo "  principal anything: it decides whether instances with no external address may"
    echo "  reach Google APIs outbound.  The agents stay --ingress=${RUN_INGRESS}."
    echo
  } >&2
  exit 2
}
