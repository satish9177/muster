# Deploying MUSTER

Two source agents on Cloud Run, one private evidence bucket, four service
identities, one control-plane job that runs the worked case against them, and
an IAM policy whose most important property is something the control plane
**cannot** do.

These deployment scripts are real and were exercised for the verified Stage-90
hero execution documented in `../ARCHITECTURE.md`. They are intended to
reproduce that environment, but they create billable Google Cloud resources.
Inspect and configure the project variables in `scripts/env.sh` before running
them; `70-verify-iam.sh`, `55-probe-job.sh`, and the hero job make the resulting
security and execution claims independently checkable.

## Order

```
PROJECT_ID=your-project ./infra/scripts/00-enable-apis.sh
PROJECT_ID=your-project ./infra/scripts/10-identities.sh
PROJECT_ID=your-project ./infra/scripts/20-site-evidence.sh
PROJECT_ID=your-project ./infra/scripts/30-secrets.sh --generate /tmp/muster-keys
PROJECT_ID=your-project ./infra/scripts/30-secrets.sh \
    /tmp/muster-keys/site-signing-key.pem /tmp/muster-keys/employer-signing-key.pem
export SIGNING_KEY_VERSION=<the version 30-secrets.sh printed>
PROJECT_ID=your-project ./infra/scripts/40-build.sh        # both images
PROJECT_ID=your-project ./infra/scripts/50-deploy.sh
PROJECT_ID=your-project ./infra/scripts/55-probe-job.sh    # the denial, as a process
PROJECT_ID=your-project ./infra/scripts/60-invoker.sh
PROJECT_ID=your-project ./infra/scripts/70-verify-iam.sh   # the denial, as a policy
PROJECT_ID=your-project ./infra/scripts/80-smoke.sh        # from inside the project
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys   # the worked run
```

That order runs the hero with `HERO_DATABASE_DEPLOYMENT=EPHEMERAL`, the default:
in-memory custody for the length of one execution, which is the shape of the run
already verified in this project and needs no database. Durable custody is an
extra provisioning step and an extra stage, and both are set out under
[Cloud SQL readiness](#cloud-sql-readiness-and-the-order-it-has-to-be-provisioned-in):

```
export HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
export DATABASE_DSN_SECRET_VERSION=<pinned>  DATABASE_MIGRATION_DSN_SECRET_VERSION=<pinned>
export DATABASE_SERVER_CA_SECRET_VERSION=<pinned>
PROJECT_ID=your-project ./infra/scripts/85-database-bootstrap.sh   # DDL, as the migrator
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

## The deliberate Action Gate mode

**Status: Cloud Action Gate support implemented, not deployed/verified.**
Nothing below has been run against Google Cloud. The verified execution this
project publishes is still the analysis-only one, and every claim about the
Gate is a claim about the local suite until a real run replaces this sentence.

`HERO_GATE_MODE` decides what the hero job does after the analysis, and the
default is the shape U1 verified:

| `HERO_GATE_MODE` | What the run does |
| --- | --- |
| `ANALYSIS_ONLY` (default) | Stops at the analysis. No gate, nothing authorized, nothing executed. |
| `CLOUD_SQL_ACTION_GATE_SANDBOX` | Runs the deterministic Action Gate over the same Cloud SQL custody, against the **synthetic sandbox executor**. No payment provider, no account, no credential, and no funds. |

The Gate mode requires `HERO_DATABASE_DEPLOYMENT=CLOUD_SQL` and is refused
under ephemeral custody, before anything is deployed: a durable execution
lifecycle kept in memory is a proof about one process, and the whole point of
the mode is a claim about a database.

It also runs **its own case**. `HERO_GATE_CASE_ID` defaults to
`CASE-RAVI-SAT-CLOUD-GATE`, and a configuration where it equals `HERO_CASE_ID`
is refused when the Gate is requested: the analysis-only case is
already-published evidence, and a Gate run that reserved an execution against it
would be writing into it.

That refusal lives in `muster::require_gate_configuration`, which
`90-hero-job.sh` calls before it deploys anything — deliberately *not* at
`env.sh` file scope. Every script here sources `env.sh` for the project, the
region and the service-account names, and bootstrap, IAM verification, teardown
and the source-agent deploys compose no Gate at all. A relationship between two
Gate case identifiers must not be able to stop a teardown.

```
export HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
export HERO_GATE_MODE=CLOUD_SQL_ACTION_GATE_SANDBOX
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

The execution's caller is the identity the **metadata server** reports for the
running job, compared against `HERO_GATE_PRINCIPAL` (the control-plane service
account by default). Nothing on that path reads a request field or an argument,
so there is no value a caller of this deployment can supply that changes who
the Gate thinks is asking. A workload running as another identity executes
nothing and creates no row.

### The retry proof

A second execution of the same deployed job reads the lifecycle the first one
recorded, confirms it, and dispatches nothing:

```
export HERO_GATE_EXECUTION_ID=<the "execution id" line the first run printed>
HERO_VERIFY_GATE_IDEMPOTENCY=1 \
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

It is an **idempotency read**, not a restart: it opens no case, appends
nothing, acquires nothing, calls no model, runs no check, reads no case head
and never reaches the executor.

The id is required because a retry names the **execution** it is asking about.
It is `sha256` over the canonical octets of the exact `ActionIntent` that was
authorized, and it is the primary key of the row those
octets live in — so it keeps naming the same historical execution however far
the case has advanced since. A retry identified from the current case head
would report a confirmed payment as absent the moment one more transcript entry
was appended, which is a duplicate-prevention story with an expiry date.

### The repeat proof

The full-repeat proof runs the complete hero path twice as two executions of
one deployed Cloud Run job. It requires an immutable, digest-pinned control
plane image and refuses before deployment when `CONTROL_PLANE_IMAGE` is only a
tag:

```
export CONTROL_PLANE_IMAGE=asia-south1-docker.pkg.dev/PROJECT/muster/control-plane@sha256:DIGEST
export HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
export HERO_GATE_MODE=CLOUD_SQL_ACTION_GATE_SANDBOX
HERO_GATE_REPEAT=1 \
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

Stage 90 deploys that image once, executes the ordinary full Gate run, and then
executes the same job with `--repeat-gate-execution`; there is no redeploy
between them. The first execution must report `CONFIRMED` with one sandbox
dispatch. The second reconstructs the same synthetic case and trust material,
replays the complete case path, re-derives the proposal and calls the existing
`ActionGate.execute()` path with a fresh executor. It must report the same
execution id and external reference, `CONFIRMED`, and zero dispatches. An
unreadable second execution is `UNDETERMINED`, not success, and mismatched
identity, reference, state, or dispatch counts fail the proof.

The repeat is not a pure read. It re-applies the stable synthetic authority and
catalog publications (their set-in-force upserts may advance publication
epochs), reopens the same construction idempotently, re-appends the same
evidence idempotently, reruns deterministic analysis, and repeats the raw-access
denial check before reaching the Gate. The durable execution row itself is not
rewritten by an exact repeat: its key, intent octets, lifecycle timestamps and
outcome remain the first execution's values.

U4 also makes the fixture-source population process-stable. The deployed Site
and Employer key references still resolve only to their configured public
halves; derived fixture keys are never used under those references. The local
two-process PostgreSQL regression proves the repeat reaches the identical
revision, certificate, execution id and external reference, and explicitly
measures that the completed second pass has no outstanding acquisition: zero
acquisition reports, zero transport requests and zero second dispatches.

The retry **names** an execution id and reads its historical row. The repeat
accepts no execution id: it **re-derives** one from the exact canonical
`ActionIntent`. The same image digest matters because certificate reproduction
is a property of the running solver build and configuration; a different build
fails closed as `PROPOSAL_REFUSED: CERTIFICATE_NOT_REPRODUCED` before any row or
dispatch.

This workflow is implemented and covered locally against PostgreSQL. It has not
been run against live Cloud SQL or Google Cloud; doing so, capturing both Cloud
Run execution names and preserving their outputs remains operator work.

### The durable case revalidation proof

U4 adds a read-only semantic proof beside the persistence and Gate proofs:

```
export HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
HERO_VERIFY_CASE_REVALIDATION=1 \
PROJECT_ID=your-project ./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

Stage 90 invokes the deployed job once with `--revalidate-durable-case`. The
fresh process reads the durable head, re-admits the stored construction,
re-verifies the pinned authority/revocation publications and every stored
attestation, reruns Q-12, replays the transcript prefix and reproduces the
stored revision and certificate. It calls no source, model, metadata authority,
Gate or executor; it derives no execution identity and opens no write scope.

Success output includes the tenant and case, revision/certificate/construction/
authorization-context digests, transcript membership count and digest, status,
`certificate reproduced true`, the number of entries reverified, `writes 0`
and `dispatches 0`. Unreadable output is `UNDETERMINED` (exit 4); a negative
revalidation is exit 1. `HERO_VERIFY_CASE_REVALIDATION` is a strict `0`/`1`
request, is refused under `EPHEMERAL`, and cannot be combined with the Gate
repeat or idempotency proof.

This revalidation and the cross-process repeat are **proven locally** with real
PostgreSQL and independent OS processes. They have **not** been run against
live Cloud SQL or as deployed Cloud Run/Job U4 executions; metadata and runtime
behaviour in such a run remain operator work.

## The worked run, in the project

`90-hero-job.sh` deploys the control plane as a **Cloud Run job** under
`muster-control-plane`, runs it once, and prints what it printed.

It is a job and not a service because the control plane here calls outbound and
is never called: a service would be an ingress nothing needs and one more thing
to hold closed. It runs the production path and stops at the analysis:

```
replay the worked case      open_case, append_transcript_entry
analyse                     an EvidenceRequest naming three propositions
route                       the fleet catalog, by source class
try to read raw evidence    under muster-control-plane -- and be refused
ask the fleet               HttpAcquisitionTransport, OIDC per audience
                            -> the deployed agents -> live Gemini
admit                       append_transcript_entry -> check Q-12
rebuild and analyse         Invariant
```

There is no gate, nothing is authorized and nothing is settled. The job exits
`0` if the case reached the invariant answer and `1` if it did not — including
if the control plane turned out to be *able* to read the site's material, which
stops the run before anything is acquired.

What it reads from the key directory is the **public half** of each signing key,
which is what a verifier holds. The private halves stay where `30-secrets.sh`
put them.

**The deployed agents sign under their own key references** —
`key-site-a-cloud-1` and `key-hr-payroll-cloud-1`, not the references the worked
case's historical record is seeded under. A verifier resolves one public key per
reference, so two different private keys must carry two different names; the job
publishes an authority snapshot granting the deployed references exactly what
the seeded ones hold, and Q-12 decides the rest.

### How the job reaches the agents

Over **Direct VPC egress**, by default, because that is the only route that
works.

The agent services are `--ingress=internal`. A Cloud Run resource calling such a
service is recognised as internal traffic **only when its request leaves through
a VPC network in the project** — default job networking is not that route. A
hero job deployed without a network attached is judged at the agent's perimeter
and refused before the agent ever sees the assignment: a 403 from Cloud Run,
surfacing as `unreached ENDPOINT_REFUSED`, which looks like the fleet is down
rather than like a network decision.

So `90-hero-job.sh` deploys the job with:

```
--network=default --subnet=default --vpc-egress=all-traffic
```

from `HERO_VPC_NETWORK`, `HERO_VPC_SUBNET` and `HERO_VPC_EGRESS` in
`scripts/env.sh`. A project that deleted its auto-mode network, or that keeps its
workloads on a named one, overrides those and nothing else; `default` and
`default` are what a new project has.

**`all-traffic`, not `private-ranges-only`.** The destination is the agent's
ordinary `run.app` URL: a public hostname at a public address. Under
`private-ranges-only` that request leaves by the default path anyway, arrives
from outside any VPC and is judged at the perimeter — exactly as if no network
had been attached. The configuration would read as correct and do nothing, which
is the worst failure available here.

This is why `00-enable-apis.sh` enables `compute.googleapis.com`. Networks and
subnets are Compute Engine resources; nothing here creates or runs a VM.

### The other half of that route: Private Google Access

`all-traffic` means *all* of it, and a Cloud Run instance on Direct VPC egress
has no external address. The agents answer at their ordinary `run.app`
hostnames, on Google front-end addresses — so unless the subnet has **Private
Google Access**, the job's outbound calls have nowhere to go.

They do not fail. They hang, until the job's own `--task-timeout` kills the
execution:

```
Terminating task because it has reached the maximum timeout of 900 seconds.
```

which mentions no network at all. This deployment paid for that once: the run
that eventually worked did so because the setting had been turned on by hand, on
a subnet — a cloud prerequisite that lived nowhere in these scripts and would
have been missing again in the next project, presenting as the fleet being down.

So `90-hero-job.sh` calls `muster::require_private_google_access` **before it
deploys anything**. It reads the subnet, enables Private Google Access if it is
off, reads it back to confirm the change took, and refuses with the exact
command if it cannot — naming the host project, which is where a Shared VPC
subnet is changed.

It is only required where the route needs it: under `private-ranges-only` a
`run.app` address is not a private range, so that request leaves by Cloud Run's
default path and this has no bearing on it. The diagnostic path attaches no
subnet at all.

**This broadens nothing.** Private Google Access decides whether an instance
with *no external address* may reach Google APIs on the way **out**. It grants
no principal anything and makes nothing reachable from outside the project: the
agents stay `--ingress=internal`, and their invoker bindings are untouched. It
is what lets the job's request arrive at that perimeter, not what gets it
through.

### Reading back what a run printed

A job outlives its executions and so do their logs, so the output of one run is
read **by that run's execution name** and never by the job's:

```
resource.type="cloud_run_job"
AND resource.labels.job_name="muster-control-plane-hero"
AND labels."run.googleapis.com/execution_name"="muster-control-plane-hero-nrrgr"
```

The name comes from the call that created the execution — `gcloud run jobs
execute --async` answers with it immediately, including for a run that will go
on to fail — and `muster::execute_job` in `scripts/env.sh` then waits for that
one execution and leaves its name in `MUSTER_EXECUTION`.

The previous version filtered on the job alone, `--order=asc --limit=200`: the
*earliest* two hundred lines the job had ever produced. A successful run whose
predecessor had timed out therefore printed the predecessor's `maximum timeout
of 900 seconds` line under the heading "what it printed". Every word of it was
true and it was evidence of a different execution.

If no execution can be named, nothing is printed. Falling back to a job-wide
read would be the original defect offered as an error path.

### How a container is told what it is

Every ordinary environment variable goes to Cloud Run through a generated file:

```
--env-vars-file=<a 0700 temp file, removed on exit>
```

and **not** through `--set-env-vars`. That flag packs every name and value into
one string split on a delimiter, and a delimiter has to be a character that
appears in no value. This deployment has twice chosen one that does:

* the comma, which is the default — `MUSTER_AGENT_PREDICATES` is itself a
  comma-separated list, so its second predicate parsed as an entry with no `=`;
* `^@^`, the repair for that — `MUSTER_AGENT_PERMITTED_CALLERS` is a
  service-account address, and it split at its own `@`:

```
ERROR: (gcloud.run.deploy) argument --set-env-vars:
Bad syntax for dict arg: [muster-agentic-2026-9177.iam.gserviceaccount.com]
```

There is no third character to pick: these values are lists, addresses, URLs,
paths and base64. The error names a value, so the repair that suggests itself is
to shorten it — drop a predicate, drop a caller — and both of those are the
removal of a control dressed as a configuration change.

The file is written by `muster::env_entry` in `scripts/env.sh`, one entry per
line as a single-quoted YAML scalar, which is the form with no escapes but one:
a quote is doubled and everything else is literal. It is created by `mktemp -d`
outside the repository and removed by a trap on exit, interrupt and termination.
A value containing a newline is refused rather than folded.

`--set-secrets` is untouched and is not this: the signing key reaches a
container as a reference to a Secret Manager version, so no key material is
written to the file or passed on any command line.

### The diagnostic escape hatch

`RUN_INGRESS=all` is **not a deployment configuration**. It exists to answer one
question during a failure — is this the network perimeter, or something above
it? — and it removes the outermost of the three controls in front of an agent,
leaving the IAM invoker binding and the agent's own caller allowlist:

```
RUN_INGRESS=all ./infra/scripts/50-deploy.sh      # diagnosis only
```

Put it back before anyone relies on the result:

```
./infra/scripts/50-deploy.sh                      # RUN_INGRESS defaults to internal
```

Nothing in the normal sequence sets it, and
`test_no_deployment_script_broadens_the_agents_ingress` fails if a script ever
starts to.

Every value is overridable: `REGION`, `VERTEX_LOCATION`, `EVIDENCE_BUCKET`,
`AGENT_MODEL`, `SIGNING_KEY_VERSION` and the rest live in `scripts/env.sh` and
read from the environment first.

Two things to get right before `50-deploy.sh`:

**`REGION` and `VERTEX_LOCATION` are two decisions, and they ship as different
values.**

| What | Variable | Ships as |
| --- | --- | --- |
| Cloud Run services and jobs | `REGION` | `asia-south1` |
| Evidence bucket (the site's raw material) | `REGION` | `asia-south1` |
| Artifact Registry, secret replicas | `REGION` | `asia-south1` |
| Vertex AI Gemini inference | `VERTEX_LOCATION` | `global` |

`VERTEX_LOCATION` used to default to `${REGION}`, which made them one value
wearing two names. They are declared independently now, because the shipped
model — `gemini-3.7-flash` — is served from the **global** Vertex endpoint, and
a deployment should not move its services and its data to follow a model.

So state the consequence rather than inherit it: **the interpretation happens
outside the region the material sits in.** What that does and does not mean:

* the site's raw material **never moves**. The objects stay in
  `EVIDENCE_BUCKET`, in `REGION`, and are read only by the source agent's own
  identity — see `20-site-evidence.sh`, and `70-verify-iam.sh`, which asserts
  that the control plane cannot read them. Nothing in this deployment copies
  them anywhere;
* what crosses is a **prompt built from that material**, by the source agent,
  inside its own container. That is a smaller thing than moving the evidence and
  it is not a nothing, which is why it is written here instead of being a
  default nobody chose.

`VERTEX_LOCATION=${REGION}` restores full co-location and is the right choice for
any model served regionally in `REGION`:

```
VERTEX_LOCATION=asia-south1 AGENT_MODEL=<a model served there> ./infra/scripts/50-deploy.sh
```

Both stay overridable, independently. The architecture suite fails if either is
ever derived from the other, or if any script places a resource at
`VERTEX_LOCATION`.

**Confirm the model is served in `VERTEX_LOCATION`.** Gemini availability is per
location and changes, which is why the pairing is checked against the live API
rather than asserted here.

`50-deploy.sh` checks this itself, against the live API, before it deploys
anything — because the failure it prevents is silent. A model that is not served
in `VERTEX_LOCATION` produces a revision that comes up, raises inside the model
client on every assignment, and returns `INTERPRETER_UNAVAILABLE` forever: a
fleet that looks exactly like a set of sources with nothing to say.

**The probe is `:countTokens`, and the check it replaced was wrong.** The
preflight used to read the publisher model as a resource:

```
GET https://${VERTEX_LOCATION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${VERTEX_LOCATION}/publishers/google/models/${AGENT_MODEL}
```

That read is **not a test of publisher Gemini availability**. It answers 404 for
models that serve requests perfectly well in the same project and the same
location. Confirmed by hand here — `gemini-3.5-flash` in `asia-south1` answers
404 to the metadata read and 200 to `:countTokens`. The pair that ships now,
`gemini-3.7-flash` at `global`, was verified the same way against this project
and answers 200.

So the old check refused deployments that would have worked, which is the worse
direction for this one to fail in. A preflight that misses a bad pair costs a
fleet that abstains until somebody notices. A preflight that refuses a good pair
costs a *decision*: the operator changes the model, or moves `VERTEX_LOCATION` —
and moving `VERTEX_LOCATION` moves where the interpretation happens, out of the
region the material sits in, for a reason that was not true.

What runs now is the API the agent itself will use:

```
POST https://${VERTEX_LOCATION}-aiplatform.googleapis.com/v1/projects/${PROJECT_ID}/locations/${VERTEX_LOCATION}/publishers/google/models/${AGENT_MODEL}:countTokens
     {"contents":[{"role":"user","parts":[{"text":"hello"}]}]}
```

`global` is not a regional prefix — for `VERTEX_LOCATION=global` the host is the
bare `aiplatform.googleapis.com`, because `global-aiplatform.googleapis.com`
resolves to nothing. That is the branch the shipped default takes.

The probe reads `VERTEX_LOCATION` and never `REGION`: what it asks about is the
inference endpoint the revision will be handed as `GOOGLE_CLOUD_LOCATION`, not
where the service is placed.

`:countTokens` and not `:generateContent`: it is served by the same publisher
model at the same location over the same path, so it answers the availability
question the same way, and it produces no completion. No tokens are generated,
no inference quota is spent, and nothing is billed for asking whether a
deployment is ready.

HTTP 200 carrying a token count is the only answer accepted. Everything else
fails closed and deploys nothing — 401, 403, 404, any other non-2xx, an endpoint
that cannot be reached, and a 200 whose body is not a count, because a 200 from
something that is not Vertex says nothing about Vertex. The refusal prints what
the endpoint answered and which of three repairs this is:

* **401** — credentials. `gcloud auth login`.
* **403** — the API is off in this project (`00-enable-apis.sh`), or this
  principal may not call Vertex AI. The deployed agents hold
  `roles/aiplatform.user`; the account running the script needs it too.
* **404** — the model is not served at this location. Two ways forward, and they
  are **not the same decision**:
  * `AGENT_MODEL=<a model served at VERTEX_LOCATION>` leaves where the model is
    called alone, so it does not change the answer to "what leaves `REGION`";
  * `VERTEX_LOCATION=<where this model is served>` keeps the model and moves the
    interpretation. The material itself never moves — it stays in the bucket in
    `REGION`, read by the source agent alone; what crosses is a prompt built from
    it, which is smaller and is not nothing.

`SKIP_MODEL_CHECK=1` proceeds anyway, for a model an operator knows is served
and the probe cannot reach.

**Note on the shipped default.** `AGENT_MODEL` defaults to `gemini-3.7-flash`
and `VERTEX_LOCATION` to `global`, because that is where that model is served —
verified in this project with `:countTokens`, HTTP 200. `REGION` stays
`asia-south1` and carries the Cloud Run services, the evidence bucket, the
registry and the secret replicas.

The pair is the decision, and overriding one half without the other is the
mistake it exists to make visible: a globally-served model deployed with a
regional `VERTEX_LOCATION` produces a fleet that comes up and abstains forever.
The preflight still runs and still calls the live API, because availability moves
and a default that outlives its model family is one that stops working silently.

**Request shape.** The agent sends no sampling configuration at all — no
`temperature`, `top_p`, `top_k` or `candidate_count`, no `thinking_budget`, and
no prefilled model turn. The two bounds it does impose live outside the request:
ADK's `max_llm_calls` and an `asyncio` wall clock. `test_request_shape.py`
captures the request ADK builds on a real run and asserts this, so a Gemini 3
incompatibility cannot be introduced by a hurried `generate_content_config=`.

**Pin `SIGNING_KEY_VERSION`.** `30-secrets.sh` adds a new secret version every
time it runs, and mounting `:latest` would let a later run rotate the key that
signs without changing `MUSTER_AGENT_KEY_REF` — the key reference the receipt
claims signed it. Check Q-12(b) would then refuse receipts from whichever
instances had restarted since, hours later, and the symptom would read as a
compromised key.

It is enforced rather than advised: `SIGNING_KEY_VERSION` has no default, and
`50-deploy.sh` refuses to deploy — before its first API call — unless the value
is a positive decimal version number. Unset, empty, `latest` and anything else
stop the run with exit 2. The check is `muster::require_signing_key_version` in
`scripts/env.sh`, and it is called from `50-deploy.sh` rather than on sourcing
because `30-secrets.sh`, which prints the version there is to pin, sources the
same file.

Two things the deployment scripts deliberately do **not** do:

* **register the agents in the fleet catalog.** `50-deploy.sh` prints the two
  service URLs and stops there. Publishing them as `endpoint_ref` is a signed
  control-plane act, and an agent that could enter itself into a catalog would
  be one step from "I am SITE-B and I can attest attendance";
* **register the signing keys in the authority registry.** `30-secrets.sh`
  prints the public halves and stops there. A key the registry has never
  granted anything produces receipts that check Q-12(b) refuses — which is
  correct, and is the fail-closed behaviour to expect if this step is skipped.

**Both are done by the control plane, and that is the distinction.** The hero
job publishes the catalog and the authority snapshot its case is judged under,
from configuration an operator handed it — a signed publication by the party
whose job that is, rather than a self-registration by the party being described.
The endpoints reach it as deployment configuration and the public keys as PEM;
neither an agent nor a script can put itself in either publication.

## Every IAM grant

| principal | role | resource | why |
|---|---|---|---|
| `muster-site-agent` | `roles/aiplatform.user` | project | calls Gemini to interpret its own material. Vertex has no narrower scope |
| `muster-employer-agent` | `roles/aiplatform.user` | project | the same, for payroll records |
| `muster-site-agent` | `roles/storage.objectViewer` | the bucket, **conditioned on `site-a/`** | reads the site's own material and nothing else's |
| `muster-employer-agent` | `roles/storage.objectViewer` | the bucket, **conditioned on `employer-1/`** | reads the employer's own records |
| `muster-site-agent` | `roles/secretmanager.secretAccessor` | the site signing secret | signs its own attestations |
| `muster-employer-agent` | `roles/secretmanager.secretAccessor` | the employer signing secret | signs its own attestations |
| `muster-build` | `roles/artifactregistry.writer`, `roles/logging.logWriter` | project | pushes the agent image. **Not** a storage reader |
| `muster-control-plane` | `roles/run.invoker` | **each service**, not the project | may ask an agent for evidence |
| `muster-control-plane` | *(nothing else, anywhere)* | — | it interprets nothing, holds no source key, and reads no source material |

The last row is the one to check. `70-verify-iam.sh` fails if it ever stops
being true.

**If — and only if — Cloud SQL is provisioned**, two more grants exist, both per
secret and neither at the project:

| principal | role | resource | why |
|---|---|---|---|
| `muster-control-plane` | `roles/secretmanager.secretAccessor` | the **runtime** DSN secret | opens a connection as a role that cannot alter the schema |
| `muster-database-migrator` | `roles/secretmanager.secretAccessor` | the **migration** DSN secret | the only identity that performs DDL |
| both | `roles/secretmanager.secretAccessor` | the server CA secret | verifies the instance rather than trusting it |
| `muster-database-migrator` | *(nothing else, anywhere)* | — | no evidence, no signing key, and not the runtime's credential |

The control plane's row above becomes "nothing else except one database
credential", and the credential it gets is deliberately the one that **cannot**
create, drop or truncate anything. The split is the point: if the control plane
could read the migration DSN, "may write rows" and "may rewrite the schema"
would be a naming convention rather than a boundary. `70-verify-iam.sh` asserts
each direction of that as a refusal, and reports `SKIP` by name — never a pass —
while the secrets do not exist.

**The build identity is on this list for a reason.** Without one,
`gcloud builds submit` runs as the project's default build or compute service
account — and in most projects the compute default carries `roles/editor`,
which includes project-wide object reads. A build could then read the evidence
bucket, and anybody able to start a build could too: a path around every
condition `20-site-evidence.sh` writes. `40-build.sh` passes
`--service-account` for exactly this reason.

## What "the control plane cannot read site evidence" means here

Stated precisely, because the loose version claims more than the policy
delivers:

* **the control plane's service identity is denied**, and `70-verify-iam.sh`
  records the denial from the storage layer itself;
* **a process running as that identity is denied**, and `55-probe-job.sh` shows
  it: a Cloud Run job in the project, running the agent image under
  `muster-control-plane`, attempting the read and exiting `3`;
* **an operator running the control plane on their own machine is outside this
  boundary.** They run under their own credentials, which in a demo project are
  usually Owner. That is a property of where the process is, not of the policy —
  and the way to close it is to run the control plane in the project under
  `muster-control-plane`, which is what the probe job demonstrates the shape of.

`70-verify-iam.sh` also asserts the *employer* agent is denied the site's
material. That is the check that makes the prefix conditions mean anything: the
control plane holds no binding at all and would be refused even by a bucket-wide
grant, so only a principal that holds a real grant on this bucket can show that
the condition narrows it.

## What this costs

Billable, and small at demo scale:

* **Cloud Run** — two services and up to three jobs (the IAM probe, the worked
  run, and the database bootstrap if Cloud SQL is provisioned), scale to zero,
  `--max-instances=2`. Nothing runs between requests, and a job bills only while
  it executes.
* **Cloud Storage** — one bucket holding a few kilobytes of synthetic material.
* **Direct VPC egress** — no charge and no resource. It attaches the hero job
  to an existing subnet rather than creating a Serverless VPC Access
  connector, so there is nothing here for `99-teardown.sh` to remove and
  nothing billing between runs.
* **Artifact Registry** — one repository holding two images: the agent runtime
  and the control plane. They are built from one submission so they cannot
  disagree about the wire contract.
* **Vertex AI** — per model call, and only when an agent is asked for evidence.
* **Secret Manager** — two secrets and two versions for the signing keys, plus
  three more if Cloud SQL is provisioned: the runtime DSN, the migration DSN and
  the server CA.
* **Cloud Build** — per build, plus the staging bucket `gcloud builds submit`
  creates for the project. That bucket holds the uploaded build context, which
  is source; `99-teardown.sh` names it and deliberately does not delete it,
  because it belongs to the project rather than to this deployment.

* **Cloud SQL** — **not created by anything here**, and the one item on this
  page that would dominate the bill if it were. An instance bills continuously
  rather than per request, whether or not a job runs, and Private Services
  Access reserves an address range on the VPC that outlives the instance.
  Deletion protection is recommended above, which also means an instance cannot
  be removed by accident — or by `99-teardown.sh`, which does not try.

`99-teardown.sh` removes all of it **except a Cloud SQL deployment**, and exits
non-zero if anything else survived.

## What is deliberately absent

* **No service account keys.** Nothing here creates or downloads one. Identity
  comes from the account attached to the revision, and impersonation in
  `70-verify-iam.sh` uses short-lived tokens.
* **No `roles/owner`, `roles/editor`, or any `*.admin`** granted to any of the
  four accounts.
* **No project-wide storage role.** Storage is granted per bucket and per
  prefix.
* **No public ingress.** Both services are `--no-allow-unauthenticated` and
  `--ingress=internal`, so `80-smoke.sh` must be run from inside the project and
  the hero job reaches them over Direct VPC egress rather than by having the
  perimeter relaxed for it.
* **No Cloud SQL instance is created by any script here.** The instance, its
  private address, its database roles and its secrets are operator-provisioned,
  in the order set out below — which has been done once and verified. Stage 90's
  default custody is still in-memory and needs none of it.
* **No client certificate.** Cloud SQL is reached with a password and a verified
  server CA. See the reasoning below; it is a subtraction, not an omission.
* **No control plane service.** The control plane calls the agents outbound and
  needs no ingress of its own for this slice. The two things deployed under its
  identity are jobs: the probe, which exists to prove a negative, and the hero
  run, which exits when it is done.
* **No settlement, in any mode.** The Gate reserves, dispatches once, and
  records an outcome against a *synthetic sandbox* executor. There is no
  payment provider, no account and no credential for one, and no mode of this
  deployment transfers real funds.
* **No cloud Action Gate has been verified yet.** The verified hero job is the
  analysis-only one: no gate, nothing authorized, nothing settled. Cloud Action
  Gate support is implemented and covered by the local suite, and it has not
  been deployed or verified against Google Cloud -- see
  [The deliberate Action Gate mode](#the-deliberate-action-gate-mode). Until a
  real run replaces that section's status line, the only executed Action Gate
  in this project is the local sandbox demo, outside this infrastructure
  slice.
* **No Terraform.** The material here is `gcloud`, so that what will be created
  can be read line by line before anything is — which is what an approval step
  is for.

## Cloud SQL durable custody, and the order it is provisioned in

**This has been provisioned and verified once, on
`muster-agentic-2026-9177` / `asia-south1`.** Instance
`muster-control-plane-db`, PostgreSQL 16, private IP only, no public IPv4,
`sslMode=ENCRYPTED_ONLY`, Data API disabled. Stage-90 execution
`muster-control-plane-hero-tsjds` authored the case; execution
`muster-s90-verify-temp-zzs9w`, a separate Cloud Run process, read the identical
durable identity back. Source commit
`6fa34c0025cfde69386aa73d0467402507cf38ac`, control-plane image
`sha256:d4139a5f4c48b81357263f3863c91ad2e590a784690752b80cf0b785796b6c31`.

**No script here creates the instance.** The steps below are the operator
procedure that was followed, written so it can be followed again in a fresh
project. Stage 90 still defaults to in-memory custody and refuses to start
durable custody it cannot prove is migrated.

There is no Firestore, no ORM, no Cloud SQL connector, no proxy sidecar and no
Google SDK in the control-plane image. `psycopg` opens an ordinary libpq
connection to a private address, and the secret-backed DSN carries TLS, a
bounded connection timeout and an application name.

### Two custodies, and Stage 90 names one

```
HERO_DATABASE_DEPLOYMENT=EPHEMERAL    (the default)
    in-memory, for the length of one execution.  No database, no secrets,
    nothing to provision -- and nothing kept.  This is the shape of the run
    already verified in the cloud, and it stays runnable.

HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
    durable PostgreSQL on a private Cloud SQL address.  Requires everything
    below.  Every way it can be unavailable ends the run: absent configuration,
    an unmigrated database, a ledger that disagrees with the build, or an
    instance that cannot be reached.  None of them falls back to memory.
```

`env.sh` refuses a value that is neither. There is no promotion and no fallback
in either direction, because "the database was unreachable" and "this run kept
nothing" are different facts and a deployment that conflated them would report
the second as the first.

### A password and a verified server, and nothing else

Cloud SQL is reached the way any PostgreSQL is: a password, carried inside the
DSN, and the instance's server CA so the server is *verified* rather than
trusted. There is no client certificate.

That is a deliberate subtraction. Cloud SQL client certificates are an optional
instance feature, and on a private address with no public IPv4, reachable only
through this project's own VPC, mutual TLS would add a second private key to
mint, mount at a mode libpq will accept, pin, and rotate — in exchange for
nothing the password and the private route do not already give. It would also
require a second secret *file*, and a Cloud Run secret volume maps to exactly
one secret and supports no subpaths, so two files under one mount directory is
not a tighter layout but a deploy-time refusal:

```text
Cannot update secret at [...] because a different secret is already mounted
in the same directory.
```

So the DSN names `sslrootcert` and must not name `sslcert` or `sslkey`;
`configuration_from_environment` refuses those rather than merely not requiring
them, because a DSN naming a client certificate would name a path Stage 90 does
not mount and would fail later, opaquely, at connect time.

### `sslmode`

`verify-ca` is the normal U1 configuration and what the DSN below uses. It
authenticates the server against the instance's own CA, which — because that CA
is specific to the instance — effectively pins the connection to it, while the
private VPC route fixes the destination.

`verify-full` is accepted but is **not** simply an upgrade you can switch on. It
additionally requires that the certificate the instance presents actually carry
the name being connected to, and a DNS name you create yourself is never in a
Cloud SQL certificate. It is reachable only when the instance is provisioned
with a CA mode that issues a hostname — `GOOGLE_MANAGED_CAS_CA`, or a
customer-managed CAS CA — and you connect to the name Cloud SQL issued for it
(`<uid>.<region>.sql.goog`), resolved through the private DNS zone that
accompanies the private address. With the legacy per-instance CA the subject is
`project:instance`, there are no DNS or IP subject-alternative names, and
`verify-full` against either a private IP or a custom name will fail the
handshake. Use `verify-ca` unless you have deliberately arranged otherwise.

### The order

Each step depends on the one before it. In particular the runtime grants come
**after** the migrator has created the schema, because until then there are no
tables to grant on and `GRANT ... ON casework.transcript_entry` errors with
`UndefinedTable`.

**1 — APIs and network prerequisites.** `00-enable-apis.sh` enables
`sqladmin.googleapis.com` and `servicenetworking.googleapis.com` along with the
rest. `10-identities.sh` creates `${MIGRATOR_SA_ID}` with no project role, like
every other identity here.

**2 — The instance.** A regional Cloud SQL for PostgreSQL instance in
`${REGION}`, PostgreSQL 16 or another version the PostgreSQL suites are run
against, with:

* private IP and **no public IPv4**;
* Private Services Access on `${HERO_VPC_NETWORK}`, reachable from
  `${HERO_VPC_SUBNET}`. Stage 90 and Stage 85 both use Direct VPC egress, so no
  Serverless VPC Access connector is needed; the peering exports subnet routes
  by default, which is what the Cloud Run instance addresses come from;
* deletion protection, backups and point-in-time recovery;
* `ssl_mode` requiring encryption. Client certificates are not required.

**3 — Database and PostgreSQL identities.** A `muster` database and two roles:

```sql
CREATE ROLE muster_migrator LOGIN PASSWORD '...';
CREATE ROLE muster_runtime  LOGIN PASSWORD '...';
CREATE DATABASE muster OWNER muster_migrator;

-- CONNECT is granted to PUBLIC by default, which would make the grant to
-- muster_runtime below decorative.  Take it away first, so that the list of
-- principals that may open a connection is the list written here.
REVOKE ALL ON DATABASE muster FROM PUBLIC;
GRANT CONNECT ON DATABASE muster TO muster_migrator, muster_runtime;
```

The migrator owns the database, which is what gives it `CREATE` for
`CREATE SCHEMA`; if it is not the owner, grant `CREATE ON DATABASE muster` to it
explicitly. The runtime role gets no ownership, `CREATE`, `DROP`, `TRUNCATE`,
role administration or database administration — ever.

**4 — Secrets, each pinned.** Four values, three secrets, and no `latest`
anywhere: `env.sh` refuses an unpinned version before anything is deployed.

| secret | contains | readable by | Stage |
|---|---|---|---|
| `${DATABASE_DSN_SECRET}` | the **runtime** DSN | `${CONTROL_PLANE_SA_ID}` | 90 |
| `${DATABASE_MIGRATION_DSN_SECRET}` | the **migration** DSN | `${MIGRATOR_SA_ID}` | 85 |
| `${DATABASE_SERVER_CA_SECRET}` | the instance's server CA | both | 85, 90 |

Grant `roles/secretmanager.secretAccessor` **per secret**, never at the project.
The control plane must not be able to read the migration DSN: that separation is
the only thing standing between "may write rows" and "may rewrite the schema",
and `70-verify-iam.sh` asserts it as a refusal.

Then export the pinned versions:

```bash
export DATABASE_DSN_SECRET_VERSION=1
export DATABASE_MIGRATION_DSN_SECRET_VERSION=1
export DATABASE_SERVER_CA_SECRET_VERSION=1
```

Both DSNs are ordinary libpq strings. U1 validates that a Cloud SQL DSN names
one non-loopback host, a database, a user, a password, an `application_name`, a
1–60 second `connect_timeout`, an absolute `sslrootcert`, and
`sslmode=verify-ca` or `verify-full`; and that it names neither `sslcert` nor
`sslkey`. A representative shape — not a credential — is:

```text
postgresql://ROLE:PASSWORD@PRIVATE_ADDRESS:5432/muster?sslmode=verify-ca&sslrootcert=/var/run/muster/cloud-sql/server-ca.pem&connect_timeout=10&application_name=muster-control-plane
```

**5 — Migrate, as the migrator.**

```bash
./infra/scripts/85-database-bootstrap.sh
```

A one-shot Cloud Run job under `${MIGRATOR_SA_ID}`, on the same network and
subnet, `--max-retries=0`, running
`python /app/demo/database_bootstrap.py --cloud-sql` from the existing
control-plane image. It applies whatever versions are missing and then re-reads
the complete ledger to prove it is current, so it is repeatable: a second run
applies nothing and still proves it. Re-run it after any image that adds a
migration, and before Stage 90.

**6 — Grant the runtime role, now that there is a schema to grant on.**

```sql
GRANT USAGE ON SCHEMA store, casework, authority, catalog, action_gate, platform
  TO muster_runtime;
GRANT SELECT, INSERT ON store.content,
  casework.transcript_entry, casework.evidence_request,
  casework.case_commitment, authority.registry_snapshot,
  authority.revocation_snapshot, catalog.agent_snapshot TO muster_runtime;
GRANT SELECT, INSERT, UPDATE ON casework.case_head,
  authority.publication_state, action_gate.execution TO muster_runtime;
GRANT SELECT ON platform.schema_migration TO muster_runtime;
```

That list is exact: it is every statement the repositories issue and no other.
`casework.case_head` needs `UPDATE` for its compare-and-set and for
`SELECT ... FOR UPDATE`; `authority.publication_state` and
`action_gate.execution` need it for `ON CONFLICT ... DO UPDATE`; everything else
inserts with `ON CONFLICT DO NOTHING` and never updates.

**A migration that adds a table does not grant on it.** The grants are
enumerated rather than defaulted, deliberately — a `GRANT ... ON ALL TABLES`
would silently widen with the schema — so **step 6 is part of applying any
future migration, not a one-time step.** Either re-run the block above after
each Stage 85, or, if you would rather it be automatic, have the migrator set
default privileges once:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE muster_migrator IN SCHEMA
  store, casework, authority, catalog, action_gate
  GRANT SELECT, INSERT, UPDATE ON TABLES TO muster_runtime;
```

That trades exactness for not forgetting. Pick one and write down which.

**7 — Prove the runtime cannot do DDL.** As `muster_runtime`, against the
provisioned database:

```sql
CREATE TABLE casework.should_be_refused (x int);   -- must fail: permission denied
DROP TABLE casework.transcript_entry;              -- must fail: must be owner
TRUNCATE casework.case_head;                       -- must fail: permission denied
```

Three refusals, or the separation in step 3 did not take.

**8 — Verify the IAM boundaries.**

```bash
./infra/scripts/70-verify-iam.sh
```

It asserts the existing evidence boundary and, once these secrets exist, the
database one: which identities may read the runtime DSN, which may read the
migration DSN, and that the migrator can reach neither the evidence bucket nor a
signing key. Before the secrets exist those checks report `SKIP` by name rather
than passing — a denial from a principal that cannot reach a secret nobody
created establishes nothing.

**9 — Deploy Stage 90 with durable custody.**

```bash
export HERO_DATABASE_DEPLOYMENT=CLOUD_SQL
./infra/scripts/90-hero-job.sh /tmp/muster-keys
```

For the durable full-repeat proof, keep the same custody configuration, pin
`CONTROL_PLANE_IMAGE` by digest, enable the deliberate Gate mode, and set
`HERO_GATE_REPEAT=1`. Stage 90 then deploys once and runs that one job twice as
described in [The repeat proof](#the-repeat-proof). `EPHEMERAL` remains the
normal default and is intentionally unrepresentable for a cross-execution
proof; durable custody is selected explicitly rather than silently promoted.

**10 — Read the run.** The job prints its custody in its configuration line and
refuses before doing any casework if the schema is not current.

### Rotation

Everything is pinned, so nothing rotates by itself and nothing rotates
silently — which also means a rotation that is not followed by a redeploy is a
deployment that keeps using the old version.

* **A password.** Change it in PostgreSQL, add a new secret version, raise
  `DATABASE_DSN_SECRET_VERSION` (or `DATABASE_MIGRATION_DSN_SECRET_VERSION`),
  re-run the stage that uses it.
* **The server CA.** Cloud SQL rotates instance CAs, and the rotation has two
  halves: the new CA is available before it is in use. Add the new certificate
  as a new secret version and raise `DATABASE_SERVER_CA_SECRET_VERSION`
  *before* completing the rotation on the instance. A pinned CA that no longer
  matches the server is a connection failure, reported as
  `DATABASE CONNECTION REFUSED: OperationalError`, on every run.

### Local PostgreSQL is unchanged

No deployment label and no cloud resource:

```powershell
$env:MUSTER_DATABASE_URL = 'postgresql://muster:muster@127.0.0.1:55432/muster'
.\.venv\Scripts\python.exe demo\database_bootstrap.py
```

The local Action Gate API keeps its existing startup migration behaviour, and
now refuses to start at all if `MUSTER_DATABASE_DEPLOYMENT=CLOUD_SQL` is set:
the two share the `MUSTER_DATABASE_URL` name, and a local tool that migrates on
startup must not be one exported variable away from doing that to the control
plane's database.

The cloud hero does not migrate. It calls the read-only current-schema check and
refuses to start if bootstrap has not been run.
## Running these on Windows

Both of these were found the hard way and are fixed in the scripts; neither
needs anything from the operator now.

**Container paths and Git Bash.** MSYS rewrites arguments that look like POSIX
paths before the program sees them, which is right for a local file and wrong
for a path inside a container. `--args=/app/demo/database_bootstrap.py` reached
Cloud Run as `C:/Program Files/Git/app/demo/database_bootstrap.py`; the job
deployed cleanly and died at runtime. `muster::gcloud_container_args` in
`env.sh` scopes the exclusion to the one invocation that carries a container
path, preserving any value the operator already set. It does **not** use
`MSYS2_ARG_CONV_EXCL='*'` or `MSYS_NO_PATHCONV=1` — both are blanket disables,
and gcloud on Windows is itself a shell script whose interpreter path must be
converted, so either one breaks gcloud rather than fixing the deployment.

**Finding a local Python.** Stage 90's last act is a local capture step. It used
to assume `python3`, which on Windows is usually an App Execution Alias: a stub
on `PATH` that exists to open the Microsoft Store and runs nothing.
`muster::require_python` establishes an interpreter by *executing* one — probing
`python3`, `python`, `py` in order — and runs before the job is deployed, because
discovering it afterwards costs a real execution, real model calls and a durable
case that a retry cannot undo. `MUSTER_PYTHON` still wins, and is probed too:

```
export MUSTER_PYTHON=/c/Python312/python.exe
```

## Teardown

```
PROJECT_ID=your-project ./infra/scripts/99-teardown.sh
```

It names everything it will delete and asks for the **bucket name** before doing
anything — the bucket is the irreversible one and is overridable from the
environment, so a stale export in a shell must not be enough. `FORCE=1` skips
the prompt.

It removes both services, **all three jobs** (probe, hero, database bootstrap),
both signing-key secrets, the repository with both images in it, the bucket and
all five service accounts — and it describes each resource before deleting it,
so "never created" and "would not delete" are told apart rather than both
reported as success. A resource it could not remove makes it exit non-zero.
`test_the_teardown_removes_every_resource_the_other_scripts_create` derives the
list from the creating scripts, so a script that creates something new fails
that test until this one removes it.

**It does not touch a Cloud SQL deployment**, and says so in the prompt. The
instance, its private-services-access range and the three database secrets are
left alone deliberately: nothing here created them, they hold the only durable
state in this deployment, and `EVIDENCE_BUCKET` has already established that a
teardown reading overridable variables can be pointed at the wrong resource by a
stale export in a shell. A database is not something to delete on that basis.
Remove it by hand, after deciding you mean it:

```
gcloud sql instances delete INSTANCE --project=PROJECT_ID
gcloud secrets delete muster-control-plane-database-url --project=PROJECT_ID
gcloud secrets delete muster-database-migration-url     --project=PROJECT_ID
gcloud secrets delete muster-cloud-sql-server-ca        --project=PROJECT_ID
```

Deletion protection is recommended when the instance is created, so the first of
those refuses until it is turned off — which is the point of it.
