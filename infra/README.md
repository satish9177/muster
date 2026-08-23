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

* **Cloud Run** — two services and two jobs (the IAM probe and the worked run),
  scale to zero, `--max-instances=2`. Nothing runs between requests, and a job
  bills only while it executes.
* **Cloud Storage** — one bucket holding a few kilobytes of synthetic material.
* **Direct VPC egress** — no charge and no resource. It attaches the hero job
  to an existing subnet rather than creating a Serverless VPC Access
  connector, so there is nothing here for `99-teardown.sh` to remove and
  nothing billing between runs.
* **Artifact Registry** — one repository holding two images: the agent runtime
  and the control plane. They are built from one submission so they cannot
  disagree about the wire contract.
* **Vertex AI** — per model call, and only when an agent is asked for evidence.
* **Secret Manager** — two secrets, two versions.
* **Cloud Build** — per build, plus the staging bucket `gcloud builds submit`
  creates for the project. That bucket holds the uploaded build context, which
  is source; `99-teardown.sh` names it and deliberately does not delete it,
  because it belongs to the project rather than to this deployment.

`99-teardown.sh` removes all of it, and exits non-zero if anything survived.

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
* **No Cloud SQL.** The control plane's database is not part of this slice; it
  is unchanged from the milestone that built it.
* **No control plane service.** The control plane calls the agents outbound and
  needs no ingress of its own for this slice. The two things deployed under its
  identity are jobs: the probe, which exists to prove a negative, and the hero
  run, which exits when it is done.
* **No cloud Action Gate and no settlement.** The verified hero job stops at
  analysis: no gate, nothing authorized, nothing settled. A PostgreSQL-backed
  Action Gate exists only in the local sandbox demo, outside this infrastructure
  slice, and it transfers no real funds.
* **No Terraform.** The material here is `gcloud`, so that what will be created
  can be read line by line before anything is — which is what an approval step
  is for.

## Teardown

```
PROJECT_ID=your-project ./infra/scripts/99-teardown.sh
```

It names everything it will delete and asks for the **bucket name** before doing
anything — the bucket is the irreversible one and is overridable from the
environment, so a stale export in a shell must not be enough. `FORCE=1` skips
the prompt.

It removes both services, **both jobs**, both secrets, the repository with both
images in it, the bucket and all four service accounts — and it describes each
resource before deleting it, so "never created" and "would not delete" are told
apart rather than both reported as success. A resource it could not remove makes
it exit non-zero. `test_the_teardown_removes_every_resource_the_other_scripts_create`
derives the list from the creating scripts, so a script that creates something
new fails that test until this one removes it.
