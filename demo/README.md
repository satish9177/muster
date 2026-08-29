# The worked run

## Durable browser demo on Windows

The browser demo keeps Ravi's Action Gate lifecycle in a PostgreSQL-backed
local sandbox Action Gate. It does not use a cloud-hosted Action Gate or a real
payment rail. No real funds are transferred.

From the repository root, use three PowerShell terminals.

Terminal 1 — create the existing PostgreSQL 16 test container once:

```powershell
docker run -d --name muster-pg -p 55432:5432 -e POSTGRES_USER=muster -e POSTGRES_PASSWORD=muster -e POSTGRES_DB=muster postgres:16-alpine
```

On later days, start the same container instead:

```powershell
docker start muster-pg
```

Terminal 2 — configure the database and start the loopback API:

```powershell
$env:MUSTER_DATABASE_URL = 'postgresql://muster:muster@127.0.0.1:55432/muster'
.\.venv\Scripts\python.exe demo\action_gate_api.py
```

Terminal 3 — start the unchanged Vite UI:

```powershell
Set-Location packages\muster-ui
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5173`. The API applies the repository's migrations and
restores the authoritative Ravi fixture idempotently on startup. If PostgreSQL
or the DSN is unavailable, the API exits instead of falling back to memory.
Vite proxies `/api/demo` to the API's default `127.0.0.1:8765`; if that port is
already occupied, free it before starting the API or configure both endpoints
consistently.

The Ravi views deliberately keep provenance separate. **Decision** projects the
stored verified cloud execution into a generated Evidence Plan. **Durable
case** reads `ravi-async-durability.json`, a separate **LOCAL POSTGRESQL
DURABILITY PROOF / SYNTHETIC DEMO / NOT CLOUD EXECUTION** artifact.

## Separate-process durable case proof

With the same local PostgreSQL container running, generate the async proof from
the repository root:

```powershell
.\.venv\Scripts\python.exe demo\async_ravi.py `
  --dsn postgresql://muster:muster@127.0.0.1:55432/muster `
  --tenant MUSTER-ASYNC-DEMO `
  --case CASE-RAVI-ASYNC-DEMO `
  prove `
  --confirm-demo-only-reset MUSTER-ASYNC-DEMO/CASE-RAVI-ASYNC-DEMO `
  --output packages\muster-ui\public\cases\ravi-async-durability.json
```

`prove` launches `employer` and `resume-site` as different Python processes.
The second phase loads the first phase's durable head and transcript before it
appends Site evidence and advances the same case. The required reset confirmation
deletes rows only for that exact synthetic tenant/case; it does not truncate
shared tables, drop migrations, touch the Action Gate demo case, or erase other
tenants. The proof simulates an asynchronous gap and claims no real elapsed time.

Before recording, stop the API and reset only the synthetic Ravi execution row:

```powershell
$env:MUSTER_DATABASE_URL = 'postgresql://muster:muster@127.0.0.1:55432/muster'
.\.venv\Scripts\python.exe demo\reset_action_gate.py --confirm-demo-only-reset MUSTER-DEMO-LOCAL-V1/CASE-RAVI-SAT-CLOUD
```

The confirmation literal and parameterized `tenant_id` + `case_id` predicate
scope this demo utility to `MUSTER-DEMO-LOCAL-V1` / `CASE-RAVI-SAT-CLOUD`. It
does not wipe the execution table, touch another case, drop PostgreSQL, or reset
migrations. Restart the API after the reset; the browser then shows the
proposal as `PROPOSED` and the Action Gate as `NOT EXECUTED`.

```powershell
.\.venv\Scripts\python.exe demo\hero.py
```

One case, three agents, one deterministic answer:

```text
WORKER AGENT
  claim      present_on_site(RAVI, SAT) = true
  by         RAVI as WORKER
  effect     none: a claim is not a justification variant

ANALYSIS BEFORE ACQUISITION
  request    <digest prefix>
  needs      scheduled(RAVI, SAT) from HR_PAYROLL_SYSTEM
  needs      present_on_site(RAVI, SAT) from SITE_ACCESS_CONTROL
  needs      on_site_duration(RAVI, SAT) from SITE_ACCESS_CONTROL

FLEET
  agent      agent-hr-payroll  at local://agent-hr-payroll
  attested   scheduled(RAVI, SAT)  admitted through Q-12
  agent      agent-site-a  at local://agent-site-a
  attested   present_on_site(RAVI, SAT)  admitted through Q-12
  attested   on_site_duration(RAVI, SAT)  admitted through Q-12

RESULT
  status     PROPOSED
  outcome    INVARIANT
  action     PAY  recipient=RAVI  amount=INR 5,100.00
  unresolved on_site_duration(RAVI, SAT), shift_payable_under_policy(RAVI, SAT)

  MUSTER has not decided that Ravi worked.  It has decided that his
  Saturday shift is payable under the pinned policy, on attested grounds.
```

The request digest prefix is printed on every run and is abbreviated above
because it is an artifact identifier rather than part of the product result.

The last line is the product claim. The case reaches an invariant answer **while
the duration is still unresolved** — the site said "at least four hours", the
policy needed four hours, and the exact number of minutes is never established,
never disclosed and never needed.

## What it actually runs

Every step invokes the production-oriented application path. `open_case`,
`append_transcript_entry`, `acquire_outstanding` and `case_status` are the
control plane's own functions; the agents use the committed ADK runtimes; the
receipts are signed by source keys and admitted through check Q-12.

There is no branch in `hero.py` that a demo takes and a deployment does not, no
answer written down in advance, and no path that skips authorization. The
acceptance suite calls the same function and asserts on what it returns, so the
run demonstrated and the run checked on every commit are one code path.

## Modes

| | |
|---|---|
| `python demo/hero.py` | deterministic interpreters, in-memory database, no network |
| `python demo/hero.py --live` | explicit hosted-model mode using the configured Gemini endpoint; not used by the browser replay |
| `python demo/hero.py --postgres DSN` | against a real database |
| `infra/scripts/90-hero-job.sh` | Stage-90 Google Cloud run captured for the verified execution replay |

The last one is `demo/cloud_hero.py`, running as a Cloud Run job under
`muster-control-plane` inside the project. Same case, same commands, same
admission path; what differs is where the processes are, which store the site
reads, and that the control plane's inability to read raw site evidence is a
fact about IAM rather than about a directory nobody pointed it at.

The tracked analysis-only Stage-90 execution acquired employer and site
evidence; it did not run all three agents. It replays Ravi's unsigned, inert text
claim rather than driving the Worker Agent, because a claim is not something a
source can be asked for and no Worker Agent was deployed. The committed Worker
Agent ADK path
does include Gemini interpretation, but it was not rerun in execution
`muster-control-plane-hero-tsjds`. The cloud run prints predicate names,
identifiers, digests, enum values and counts — and never
a `detail` field, a model's words, an object body, a token or a key. See
`infra/README.md`.

`--live` needs an agent configured the way a deployment configures one —
`MUSTER_AGENT_MODEL`, `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` and the
rest; see `packages/muster-agents/src/muster/agents/config.py`. As shipped that
is `gemini-3.7-flash` at `GOOGLE_CLOUD_LOCATION=global`, while the Cloud Run
services and the evidence bucket stay in `asia-south1` — the model location and
the deployment region are separate values, and only the source agent reads the
material. Without it, the run uses the deterministic interpreters and reaches
the same answer. **The consequential result remains reproducible because
candidate interpretations pass through deterministic validation, authority,
and pinned policy.**

## What the three agents are given

| agent | material | may attest | key |
|---|---|---|---|
| Worker | Ravi's own message, in his own words | *nothing* — an inert claim | — |
| Employer | a weekly payroll and roster export | `scheduled`, `daily_rate` at RECORD | `key-hr-payroll-1` |
| Site | a north-gate access log and an attendance board photograph | `present_on_site`, `on_site_duration` at OBSERVATION | `key-site-a-1` |

Those are the keys the worked case is *seeded* under. A deployed agent holds a
key this repository never generated and signs under its own reference —
`key-site-a-cloud-1`, `key-hr-payroll-cloud-1` — because a verifier resolves one
public key per reference, and two different private keys under one name is a
state the authority registry cannot represent.

The material is synthetic and lives in `packages/muster-agents/fixtures/`. The
attendance board is generated by `fixtures/render_attendance_board.py`, so the
one binary artifact in the repository is reproducible rather than an opaque blob
somebody once made.

In the tracked analysis-only Stage-90 acquisition, the Employer Agent received a
`text/plain` source, Gemini 3.7 Flash produced candidate facts, deterministic
code validated them, the agent signed a narrow attestation, and Q-12 checked
it. The Site Agent sent raw PNG bytes plus text through ADK to Gemini; candidate
facts were then validated, signed, and checked by Q-12.

The Control Plane identity was denied access to Site-A raw evidence by GCP IAM;
the Site Agent identity was allowed. Locally the same synthetic material lives
in a directory behind the same acquisition port.

Gemini interprets source-local evidence and produces candidate facts.
Deterministic code validates authority, applies pinned policy, determines
consequential outcomes, and controls execution.

## What it does not claim

It does not decide, or say, that Ravi worked. It decides that his Saturday shift
is **payable under the pinned policy on attested grounds**. The stronger
sentence is not ours to say, and a reader who notices we said it has found a
real defect rather than a quibble.
