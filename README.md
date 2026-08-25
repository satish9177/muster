# MUSTER

> **When records disagree, MUSTER proves only what matters — and acts only on what can be proved.**

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

**Fastest local proof:** with Python 3.12 and the packages installed, run
`.\.venv\Scripts\python.exe demo\hero.py` from the repository root. It is
deterministic and makes no network or model call.

```text
Gemini interprets.
Sources attest.
Policy determines consequences.
Deterministic controls authorize execution.
```

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
configuration. The verified Stage-90 cloud run remains the keyless Vertex AI
Employer/Site path and did not rerun the Worker Agent.

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

After dispatch, an uncertain outcome is never automatically redispatched. The
current implementation uses local PostgreSQL and a local sandbox executor; no
real funds are transferred. The Action Gate was not part of the verified
Stage-90 cloud execution.

## Verified Google Cloud Execution

The Stage-90 hero was verified in project `muster-agentic-2026-9177`:

| Item | Verified value |
|---|---|
| Cloud Run / Cloud Storage region | `asia-south1` |
| Vertex AI | Gemini 3.7 Flash at `global` |
| Cloud Run services | `muster-site-agent`, `muster-employer-agent` |
| Cloud Run job | `muster-control-plane-hero` |
| Verified execution | `muster-control-plane-hero-htkpt` |

That execution verified the Employer Agent, Site Agent, genuine Gemini
interpretation, the Control Plane IAM 403, Q-12 admission, deterministic
`INVARIANT`, and certificate rebuild. It did **not** rerun the Worker Agent or
run the Action Gate, local PostgreSQL, procurement proof, or local Vite UI. See
[ARCHITECTURE.md](ARCHITECTURE.md) for the exact cloud/local boundary.

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
| Semantic restart / resume / cross-process re-validation | **not yet** |
| Cloud Action Gate | **not implemented, not executed** |
| Real funds transferred | **no** |

Stage 90 still defaults to `HERO_DATABASE_DEPLOYMENT=EPHEMERAL`; durable custody
is named explicitly with `CLOUD_SQL` and never fallen back to.

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

The current tree collects **2,359 tests**. The latest complete validation
accounts for **2,075 passed, 284 skipped, 0 unresolved failures**. The skipped
cases are environment-dependent PostgreSQL, cloud, and live-model tests that
require the appropriate DSN, credentials, or environment; they do not indicate
broken or unfinished behavior.

Install the pinned developer tools once, then run the suite:

```powershell
.\.venv\Scripts\python.exe -m pip install --group dev
.\.venv\Scripts\python.exe -m pytest
```

Coverage includes deterministic kernel behavior, authority and Q-12, Action
Gate concurrency/finality/idempotency, PostgreSQL integration, agent
integrations, the procurement tolerance flip, and architecture/import
contracts. Set `MUSTER_TEST_DSN` and the documented live-model environment only
when intentionally running those integration paths.

## Demo / Submission

- Demo video: [to be added before submission]
- Devpost: [to be added before submission]

## Limitations / Scope

The submission uses synthetic enterprise fixtures. Action execution is a local
sandbox with no real payment rail; the Action Gate and PostgreSQL were not part
of the verified Stage-90 cloud run. The UI currently runs locally. Cloud Run
and Cloud Storage are in `asia-south1`, while Vertex inference uses the
`global` location. These are the current submission boundaries.
