# MUSTER

> **When records disagree, MUSTER proves only what matters — and acts only on what can be proved.**

**The problem.** High-impact enterprise agents act over records that belong to
different institutions — payroll, a site's attendance board, a worker's own
account. Centralizing every raw record into one control plane is unsafe. And when an
irreversible action has already been sent and its outcome is unknown, blindly
retrying it is unsafe too.

**The twist.** MUSTER asks only for evidence capable of changing the
consequence. Its deterministic kernel enumerates every action still reachable
under pinned policy; when they all agree, acquisition stops and the exact fact
stays unknown. Asking for less is the safety property, not a shortcut.

**The security boundary is real.** In the verified cloud run, the central
Control Plane was genuinely denied Site-A's raw evidence — a real GCP IAM
**HTTP 403**. Only the authorized, source-local Site Agent read it, and only
narrow signed attestations came back.

**The model boundary.**

```text
Gemma / Gemini interpret.
Sources attest.
Deterministic MUSTER authorizes.
```

Gemma 4 is used only by the optional local `--live` Worker claim-intake path.
Its output is unsigned and institutionally inert. Gemma was **not** part of the
verified Stage-90 institutional cloud execution or the final GCP Action Gate
proof, both of which ran Gemini 3.7 Flash on Vertex AI for the Employer and
Site source agents only.

**The execution proof.** On Cloud Run and Cloud SQL, a synthetic external
action was accepted exactly once and its answer was deliberately lost. MUSTER
recorded `UNCERTAIN` rather than guessing. An independent read of the external
system found the transfer already there. A fresh Cloud Run process reconciled
the same execution to `CONFIRMED` by observation, and an exact repeat returned
that record without dispatching:

| Transfer before reconcile | Reconciliation dispatches | Exact repeat dispatches | Final transfer count |
|---|---|---|---|
| 1 | 0 | 0 | 1 |

**SANDBOX ONLY. NO REAL FUNDS TRANSFERRED.** The rail is a simulated external
system, not a payment provider. This was *unknown after acceptance*; no Cloud
Run process was killed, and no screen here is live telemetry.

## Start here

| | |
|---|---|
| **Hosted replay** | [Public Cloud Run replay](https://muster-judge-replay-867434431401.asia-south1.run.app) — read-only verified replay, not live telemetry, with no backend or mutation endpoint. |
| **Demo video** | *Not recorded yet.* |
| **Repository** | <https://github.com/satish9177/muster> |
| **Architecture** | [Diagram](assets/muster-architecture.png) · [ARCHITECTURE.md](ARCHITECTURE.md) |
| **Final proof receipt** | [The five named executions](ARCHITECTURE.md#final-live-unknown-after-acceptance-and-reconciliation-proof) · tracked record: `packages/muster-ui/public/cases/ravi-cloud-gate-proof.json` |
| **60-second local proof** | `.\.venv\Scripts\python.exe demo\hero.py` — deterministic, offline, no model call |

Hosted UI provenance is source commit `c464d1527d7aee6d6903c652be69c979e69b48b4`, Cloud Build `9236f768-2e0a-4ae4-99af-d9b676c18fd7`, and Cloud Run revision `muster-judge-replay-00002-vs8`; it is separate from the frozen Action Gate proof provenance at source commit `af1359c828d70e9e860f10ae076f225b006e5693`.

---

MUSTER is a consequence-sensitive evidence and execution system for enterprise
agents. A worker says a Saturday shift should be paid, while payroll, schedule,
and site evidence belong to different institutional sources. Rather than
centralizing every record and asking one model to decide, MUSTER identifies
which unresolved facts could change the action, routes narrow requests to
authorized source agents, and uses Gemini to interpret messy text and visual
evidence. Deterministic controls then validate candidate facts, check
institutional authority, apply pinned policy, reproduce the consequence, and
authorize execution separately. The result is not a claim that MUSTER proved
objectively that Ravi worked; it is a defensible decision that Saturday is
payable under the pinned policy on authorized attested grounds.

## Why This Is Different

A typical agent workflow gathers data, prompts a model, and acts. MUSTER puts
consequential uncertainty and institutional authority in the middle:

```text
determine consequential uncertainty
    ↓
request only relevant authorized evidence
    ↓
Gemini interprets source material
    ↓
deterministic validation + source authority
    ↓
pinned policy
    ↓
reproducible consequence
    ↓
Action Gate
```

This is **consequence-sensitive evidence acquisition**: MUSTER asks for more
evidence only when its value could change the action.

The Ravi Decision view now exposes that plan directly: it distinguishes facts
that were required and resolved from the exact duration that remains unresolved
but can no longer change the one reachable action. The procurement policy
switch applies the same test to one fixed-price and four per-unit outcomes.

## 60-Second Local Proof

From the repository root:

```powershell
.\.venv\Scripts\python.exe demo\hero.py
```

The verified run starts with Ravi's self-reported claim as inert, admits narrow
authorized evidence, and reaches an `INVARIANT` outcome while exact on-site
duration remains unresolved. It proposes `PAY RAVI INR 5,100`; **INR 5,100 is
the corrected weekly total**, not the Saturday-only amount. This path uses
deterministic interpreters, an in-memory database, and no network.

For a fresh clone, create the Python environment once:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install `
  -e .\packages\muster-kernel `
  -e .\packages\muster-platform `
  -e .\packages\muster-agents
```

## Architecture

![MUSTER architecture](assets/muster-architecture.png)

[Open or download the full-size SVG](assets/muster-architecture.svg) ·
[Read the authoritative architecture document](ARCHITECTURE.md)

The SVG is the source and the PNG is derived from it. Regenerate the PNG with
`assets/render-architecture.sh`, which renders the SVG through headless Chrome
at a pinned size and scale so the two cannot drift apart.

## Full Interactive Demo

Prerequisites: Python 3.12, Docker, and Node.js/npm. From the repository root,
use three Windows PowerShell terminals.

### 1. PostgreSQL

Start the existing demo container:

```powershell
docker start muster-pg
```

If it does not exist, create it once:

```powershell
docker run -d --name muster-pg -p 55432:5432 `
  -e POSTGRES_USER=muster `
  -e POSTGRES_PASSWORD=muster `
  -e POSTGRES_DB=muster `
  postgres:16-alpine
```

### 2. Action Gate API

```powershell
$env:MUSTER_DATABASE_URL = 'postgresql://muster:muster@127.0.0.1:55432/muster'
.\.venv\Scripts\python.exe demo\action_gate_api.py
```

### 3. Local UI

```powershell
Set-Location packages\muster-ui
npm.cmd install
npm.cmd run dev
```

Open <http://127.0.0.1:5173>.

### Replay-only judge build

`npm run build` produces the **replay-only** bundle by default: no `/api/demo`
call, no Action Gate mutation control, no database and no credential. It needs
no backend at all, and it is the bundle the hosted page serves.

```powershell
Set-Location packages\muster-ui
npm.cmd run build
Set-Location dist
python -m http.server 5000    # or any static server
```

`npm run dev` keeps the local PostgreSQL Action Gate controls, because the mode
resolves from the build kind and fails closed. To be explicit either way, build
with `VITE_MUSTER_LOCAL_GATE=true` or `=false`.

To host it later — **not deployed yet** — see
[the public judge-replay page](infra/README.md#the-public-judge-replay-page).

### Safe demo reset

Stop the API first. Then, from the repository root, run:

```powershell
$env:MUSTER_DATABASE_URL = 'postgresql://muster:muster@127.0.0.1:55432/muster'
.\.venv\Scripts\python.exe demo\reset_action_gate.py `
  --confirm-demo-only-reset MUSTER-DEMO-LOCAL-V1/CASE-RAVI-SAT-CLOUD
```

The reset is restricted to the synthetic `MUSTER-DEMO-LOCAL-V1` tenant and
`CASE-RAVI-SAT-CLOUD` case. It deletes only that demo execution row; it does
not wipe the Action Gate table. Restart the API after resetting.

## Demo Cases

### Ravi Workforce

Ravi's daily rate is INR 850. Under the pinned workforce policy, Saturday
becomes payable when the following narrow facts are admitted:

```text
scheduled(RAVI,SAT) = true
present_on_site(RAVI,SAT) = true
on_site_duration(RAVI,SAT) >= 508 minutes
```

The policy needs at least 240 minutes. Every admissible duration therefore
produces the same action, so the result is `INVARIANT` even though exact
duration stays unresolved. The proposal is `PAY RAVI INR 5,100`, the corrected
weekly total: six payable days at INR 850.

**What the amount means.** The fixture also records INR 4,250 already paid for
the week, and the sandbox action represents the *corrected weekly payroll
instruction* rather than a top-up of the difference. A production payroll
adapter would need an explicit replace-versus-delta settlement contract before
either reading could be called correct. What the sandbox proof demonstrates is
execution and reconciliation safety — one external effect, zero redispatch —
not production payroll settlement accounting.

### Procurement PO-4821

For PO-4821, the known quantity is `97 <= quantity <= 100`. A fixed-price
contract pays INR 63,000 at every admissible quantity, so the result is
`INVARIANT` and no extra evidence is needed. A per-unit contract produces
different totals, so the result is `DIVERGENT` and exact quantity now matters.

This local deterministic proof shows that the kernel is consequence-sensitive
and domain-independent. Procurement was not run in the verified cloud hero.

### Durable asynchronous continuation

Institutional evidence does not have to arrive in one synchronous prompt.
`demo/async_ravi.py` persists the synthetic Ravi case in local PostgreSQL,
exits the employer phase, and resumes the same case in a separate process when
the Site event arrives. Its versioned proof records both process IDs, the
before/after durable heads and transcript identity, and the final invariant
result. This is a **local PostgreSQL durability proof**, not Cloud SQL or cloud
execution; the gap is simulated and no elapsed production time is claimed.

## Google AI Model Responsibilities

In this integration, the model tier follows the trust tier:

- **Additional Google AI model — Gemma 4 (`gemma-4-26b-a4b-it`):** handles
  low-trust Worker claim intake in the optional local `demo/hero.py --live`
  path. It is accessed through
  Google's hosted Gemini Developer API. Its candidate must pass the existing
  deterministic claim validator and becomes only an unsigned, institutionally
  inert `StatementRecord`; Gemma does not attest it or decide payment.
- **Gemini 3.7 Flash** runs through Vertex AI for Employer and Site
  institutional evidence interpretation. Those source agents deterministically
  validate candidates, sign narrow attestations, and submit them to Q-12.
- **Deterministic MUSTER controls** remain responsible for authority, pinned
  policy, consequence evaluation, certificate reproduction, and execution
  eligibility.

The default `python demo/hero.py` remains deterministic and offline. Only the
explicit `--live` mode constructs hosted models; the Worker Developer backend
reads its API key from the environment and no key is stored in MUSTER
configuration. The tracked analysis-only Stage-90 cloud run remains the keyless
Vertex AI Employer/Site path and did not rerun the Worker Agent.

## Why Gemini Is Essential for Institutional Evidence

The verified Site-A path combines two evidence formats:

```text
attendance-board-sat.png + gate-log-sat.txt
    ↓
Site Agent
    ↓
Google ADK
    ↓
Gemini 3.7 Flash on Vertex AI (global)
    ↓
candidate facts
    ↓
deterministic validation
    ↓
source signature
```

The Site Agent sends the raw PNG through ADK `inline_data` together with text.
Gemini supplies flexible multimodal interpretation, avoiding brittle
format-specific extraction logic for every visual and text layout. New source
domains may still need adapters, permissions, schemas, and authority setup.
MUSTER supplies authority, policy, reproducibility, and execution control after
interpretation.

## Security / Authority

- The Fleet Catalog routes an address; it grants no authority.
- GCP IAM isolates source access. A Control Plane read of raw Site-A material
  received a real HTTP 403.
- Q-12 checks institutional authority across key, principal, tenant, source
  class, predicate, resource, validity, and revocation. Signed does not mean
  authorized.
- Raw evidence never reaches the MUSTER Control Plane. An authorized source
  agent may send necessary evidence content to Vertex AI at the `global`
  location; only validated, signed narrow attestations enter MUSTER.

## Action Gate

The Action Gate is deterministic code, not an AI agent. It binds execution
authority to the exact proposed action, separately from Q-12 evidence
authority, and uses a durable PostgreSQL reservation:

```text
RESERVED → DISPATCHED → CONFIRMED | FAILED | UNCERTAIN
```

After dispatch, an uncertain outcome is never automatically redispatched, and a
retry of an already-durable execution is an *idempotency read*: it returns the
recorded lifecycle without crossing the executor boundary again.

`RESERVED` is not a stuck state and has no separate recovery API. It is the
state machine's proof that dispatch has *not* occurred, and `execute()` already
carries a durable reservation forward: a later process re-derives the same
execution key, finds the row, and attempts the `RESERVED → DISPATCHED`
conditional update, which is itself the single-winner ownership mechanism.

A row left `DISPATCHED` or `UNCERTAIN` is different, because an external effect
may already have happened. Those are **reconciled**, not retried:
`reconcile_execution` asks the executor's own durable record what actually
happened, and applies the answer to the existing row.

```text
DISPATCHED → CONFIRMED | FAILED | UNCERTAIN
UNCERTAIN  → CONFIRMED | FAILED
```

`CONFIRMED` and `FAILED` stay final, `RESERVED` is not reconciled through this
API, and reconciliation has **no redispatch path at all**. The executor is
authoritative for the effect it owns: MUSTER never infers an outcome from
elapsed time, process death, a missing finalize, or local memory, and there is
no lease, timeout, heartbeat or background reconciler. Many reconcilers may
inspect concurrently because inspection never dispatches or creates the effect;
exactly one durable Gate compare-and-swap changes the row, and every loser is
handed the winner's record. The sandbox external-world protocol may atomically
seal a never-attempted idempotency key with durable negative evidence, which
prevents a later dispatch from starting and makes `NotExecuted` provable.
Each reconciled row records `reconciled_from` and `reconciled_at`, which the
read model and the UI surface as provenance without ever changing the state or
the finality it reports.

The reconcilable executor used by the proofs keeps its record in a separate
`sandbox_rail` PostgreSQL schema, on its own connection, so the executor's world
survives the death of the MUSTER process. It commits `ATTEMPTED` before the
transfer; an attempted key without a visible transfer remains unknown, and only
a completed transfer or durable explicit negative evidence resolves it. **That rail is a simulated external
system: it transfers no real funds, it is not a payment provider or a payment
rail, and it is not production financial infrastructure.**

A retry names that execution by its **execution key** — `sha256` over the
canonical octets of the exact authorized `ActionIntent`, and the primary key of
the row holding them. Nothing about that identity comes from the case's current
state, so a confirmed execution stays addressable after the case head moves on.

Both the local demo and the deployed Cloud SQL composition use a **synthetic
sandbox executor**. There is no payment provider and no credential for one, and
no real funds are transferred in any mode.

**The Cloud SQL sandbox Action Gate and executor reconciliation are now
live-verified.** In the final GCP proof, a synthetic executor accepted one action
and deliberately lost the answer, so the Gate durably recorded `UNCERTAIN`. An
independent read found the simulated external transfer before reconciliation; a
fresh Cloud Run process reconciled it to `CONFIRMED` with zero redispatch; an
exact execution-key read dispatched nothing; and the final external-world read
still found exactly one transfer. This was unknown after acceptance, not Cloud
Run process death. The literal process-death proof remains local in
`demo/reconcile_ravi.py`.

**SANDBOX ONLY. NO REAL FUNDS TRANSFERRED.** The deployed proof used a simulated
external system, not a payment provider or payment rail. See
[ARCHITECTURE.md](ARCHITECTURE.md#final-live-unknown-after-acceptance-and-reconciliation-proof)
for the immutable build provenance and the five named proof executions.

## Verified Google Cloud Executions

The analysis-only trace and the later final Gate proof were verified in project
`muster-agentic-2026-9177`:

| Item | Verified value |
|---|---|
| Cloud Run / Cloud Storage region | `asia-south1` |
| Vertex AI | Gemini 3.7 Flash at `global` |
| Cloud Run services | `muster-site-agent`, `muster-employer-agent` |
| Cloud Run jobs | `muster-control-plane-hero`, `muster-database-bootstrap`, `muster-control-plane-probe` |
| Tracked analysis-only trace | `muster-control-plane-hero-tsjds` |
| Final Gate proof case | `CASE-RAVI-SAT-CLOUD-GATE-FINAL-B-AF1359C` |
| Final Gate execution id | `6e9de1415fb0056e7c2e41b4b3d1d15008a980e0b19a7afde70c86f0642d5b80` |
| Deployed source commit — built and ran this proof | `af1359c828d70e9e860f10ae076f225b006e5693` |
| Cloud Build | `4f7f281f-5373-43db-addd-496cd2c546fe` (`SUCCESS`) |
| Immutable image digest | `sha256:77e0060833b982b471b7b7e272ee37eb438e3e551e79ba004cb41e94ca2e9d73` |

The analysis-only trace verified the Employer Agent, Site Agent, genuine Gemini
interpretation, the Control Plane IAM 403, Q-12 admission, deterministic
`INVARIANT`, and certificate rebuild. It did **not** rerun the Worker Agent or
run the Action Gate, local PostgreSQL, procurement proof, or local Vite UI. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the exact cloud/local boundary.

The separate final Gate case verified unknown-after-acceptance handling,
independent external-world evidence before reconciliation, reconciliation from
a fresh Cloud Run process with zero redispatch, an exact durable idempotency read
with zero dispatches, and one unchanged synthetic transfer afterward.

## Google Cloud Services Used

- Cloud Run
- Cloud Storage
- Vertex AI
- Secret Manager
- IAM
- Artifact Registry
- Cloud Build
- Cloud SQL for PostgreSQL (private IP only)

**Cloud SQL durable custody is provisioned and verified on GCP.** A Stage-90
execution wrote the worked case to a private Cloud SQL instance, and a second,
independent Cloud Run execution read the identical durable identity back out of
it. Provenance is in `ARCHITECTURE.md`; the procedure is in `infra/README.md`.

What that verifies, and what it does not:

| | |
|---|---|
| Persistence across independent Cloud Run executions | **verified** |
| Control Plane denied raw Site-A evidence (HTTP 403) | **verified** |
| Durable semantic revalidation | **verified locally and on the earlier deployed Cloud Run proof `CASE-RAVI-SAT-CLOUD-GATE-U5B`; not repeated on final `af1359c` image** |
| Cross-process / full repeat | **verified locally and on that earlier deployed Cloud Run proof; not repeated on final `af1359c` image** |
| Cloud Action Gate | **verified with the synthetic Cloud SQL sandbox executor** |
| Cloud executor reconciliation | **verified for deliberate unknown after acceptance; zero redispatch** |
| Real funds transferred | **no** |

Stage 90 still defaults to `HERO_DATABASE_DEPLOYMENT=EPHEMERAL`; durable custody
is named explicitly with `CLOUD_SQL` and never fallen back to.

The local U4 proof re-admits the stored construction, re-verifies every stored
entry and pinned authority publication, reruns Q-12, replays the transcript and
reproduces the certificate from a fresh interpreter. It opens only a database
read scope and reports zero writes and zero dispatches. The earlier deployed
Cloud Run proof `CASE-RAVI-SAT-CLOUD-GATE-U5B`, whose durable execution identity
begins `bfa1d0ba`, also established durable case revalidation and the
cross-process/full repeat. The final `af1359c` provenance run did not repeat
those demonstrations.

## Repository Structure

```text
packages/muster-kernel    deterministic decision kernel
packages/muster-platform  control plane, Q-12, custody, and Action Gate
packages/muster-agents    Google ADK agents and Google AI model integrations
packages/muster-ui        local React/TypeScript case viewer
demo                      deterministic hero and local browser API
infra                     Google Cloud deployment and verification scripts
ARCHITECTURE.md            authoritative architecture and claim boundaries
```

## Testing

`pytest --collect-only` reports **7,706 collected tests** — items, which is
what pytest runs and counts, so a parametrized test contributes one per case.
**0 fail in either environment recorded here.** How many of the 7,706 *run* is
a property of the machine rather than of the tree, so the counts are given per
environment rather than as one number:

| Environment | Passed | Skipped | Failed |
|---|---|---|---|
| Windows 11 · Python 3.12 · a POSIX shell on `PATH` (Git Bash) | 7,318 | 388 | 0 |
| Windows 11 · Python 3.12 · no POSIX shell on `PATH` (PowerShell) | 7,210 | 496 | 0 |
| `ubuntu-24.04` via `.github/workflows/verify.yml` | *not yet run* | *not yet run* | *not yet run* |

Each Windows row is one complete `python -m pytest` of the whole tree. Neither
has a DSN or cloud credentials, so both skip the PostgreSQL, cloud and
live-model suites; those are reported as skips rather than hidden and do not
indicate broken behavior. **The two rows differ by exactly 108 tests, and the
difference is the shell.** Many suites drive the deployment scripts through a
real `bash` and resolve one by running it (see the note below); where no POSIX
shell answers the probe, those 108 skip instead of failing. That is the whole
of the gap.

**No Linux run is recorded in this repository yet**, and none is claimed.
`.github/workflows/verify.yml` runs ruff, mypy, all three import-linter
configurations and pytest on `ubuntu-24.04`, plus the UI's three commands, and
is the intended source of a supported-platform number. Until GitHub has
actually run it after a push, the third row stays empty.

The UI has **119 Vitest tests across 11 files**, all passing, alongside
`npm run typecheck` and `npm run build`.

**A note on the platform, because the counts depend on it.** Many suites drive
the deployment shell scripts through a real `bash`, and on Windows the first
`bash` on `PATH` is usually a WSL launcher — `System32\bash.exe` or the
`WindowsApps` alias — which starts a Linux distribution whose filesystem is not
this one. Handed a script named `C:/…/drive.sh`, it fails, and a hundred tests
fail with it for a reason that has nothing to do with the scripts. The suites
now resolve a shell by *running* one: candidates are tried in `PATH` order and
the first that executes a probe script named by a real path is used. On a
machine with no POSIX shell at all, those suites **skip** rather than fail, and
say so — which is exactly why the two Windows rows above differ, and why
reporting one universal pass/skip pair for this tree would be false on at
least one of them.

Install the pinned developer tools once, then run the suite:

```powershell
.\.venv\Scripts\python.exe -m pip install --group dev
.\.venv\Scripts\python.exe -m pytest
```

Coverage includes deterministic kernel behavior, authority and Q-12, Action
Gate concurrency/finality/idempotency, PostgreSQL integration, agent
integrations, the procurement tolerance flip, the tracked final Gate proof
record, the replay-only hosting properties, and architecture/import contracts.
Set `MUSTER_TEST_DSN` and the documented live-model environment only when
intentionally running those integration paths.

## Demo / Submission

- Hosted replay: [public read-only verified replay](https://muster-judge-replay-867434431401.asia-south1.run.app) — not live telemetry, with no backend or mutation endpoint
- Demo video: [to be added before submission]
- Devpost: [to be added before submission]

## Limitations / Scope

The submission uses synthetic enterprise fixtures. Action execution is a
sandbox with no real payment rail. The final Cloud Action Gate proof used Cloud
Run, Cloud SQL and a simulated external system; it did not transfer real funds
and did not kill the Cloud Run process. Literal process death remains the local
PostgreSQL proof. Durable revalidation and full re-derivation repeat were
established on an earlier deployed Cloud Run proof but were not repeated on the
final `af1359c` image. The UI currently runs locally. Cloud Run and Cloud Storage
are in `asia-south1`, while Vertex inference uses the `global` location. These
are the current submission boundaries.
