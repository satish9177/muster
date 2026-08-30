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
stays unknown.

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
Run process was killed, and nothing shown is live telemetry.

**Start here.** Hosted replay: [public read-only verified replay](https://muster-judge-replay-867434431401.asia-south1.run.app) — not live telemetry, with no backend or mutation endpoint. Demo video: *not recorded
yet*. Repository: <https://github.com/satish9177/muster> ·
[Architecture](https://github.com/satish9177/muster/blob/main/ARCHITECTURE.md) ·
[Final proof receipt](https://github.com/satish9177/muster/blob/main/ARCHITECTURE.md#final-live-unknown-after-acceptance-and-reconciliation-proof)

Hosted UI provenance is source commit `c464d1527d7aee6d6903c652be69c979e69b48b4`, Cloud Build `9236f768-2e0a-4ae4-99af-d9b676c18fd7`, and Cloud Run revision `muster-judge-replay-00002-vs8`; it is separate from the frozen Action Gate proof provenance at source commit `af1359c828d70e9e860f10ae076f225b006e5693`.

## Inspiration / Problem

A worker says a Saturday shift should be payable. Payroll knows the rate and
schedule; a site controls its attendance board and gate log; the worker has his
own account. Those records can disagree, and they should not all be copied into
one central agent just to answer a narrow question.

The challenge is determining which fact can change the consequence, who may
attest it, which policy applies, and whether execution is safe.

## What It Does

MUSTER autonomously determines which unresolved facts can still change the
consequential action. Its deterministic kernel enumerates the reachable
consequences under pinned policy before requesting more evidence. If the action
can change, MUSTER emits a narrow request for the consequential propositions
and routes it to an appropriate source agent. If every admissible state already
produces one action, acquisition stops.

Authorized source agents use Gemini to interpret messy text and images.
Deterministic validation checks candidates; sources sign narrow attestations;
Q-12 checks authority; pinned policy determines the consequence; and a separate
Action Gate controls execution.

In the workforce case, the authorized site evidence establishes a lower bound
of at least 508 minutes while exact duration remains unresolved. Because every
admissible duration already leads to the same policy consequence, MUSTER can
authorize the corrected weekly payout without acquiring an exact duration. It
concludes that Saturday is payable under pinned policy on authorized attested
grounds; it does not claim to prove objectively that Ravi worked. The proposal
is `PAY RAVI INR 5,100`, the corrected weekly total.

The fixture also records INR 4,250 already paid for the week, and the sandbox
action represents the corrected weekly payroll *instruction* rather than a
top-up of the difference. A production payroll adapter would need an explicit
replace-versus-delta settlement contract. What the sandbox proof demonstrates is
execution and reconciliation safety, not production payroll settlement
accounting.

The judge-facing Evidence Plan makes the stopping rule visible: MUSTER
determines which unresolved facts can still change the action before requesting
more evidence. It shows the threshold evidence that mattered alongside the
exact duration that remains unresolved because only one consequential action is
reachable.

## How We Built It

The Python kernel and control plane integrate with Google ADK agents at two
trust tiers. Gemma 4 (`gemma-4-26b-a4b-it`) handles low-trust Worker claim
intake through Google's hosted Gemini Developer API in the optional local live
path; the result is an unsigned, institutionally inert `StatementRecord`.
Gemini 3.7 Flash interprets Employer and Site institutional evidence through
Vertex AI. Cloud Run hosts those source agents in `asia-south1`; Cloud Storage
holds synthetic evidence; IAM isolates identities; and Secret Manager holds
their signing keys.

A PostgreSQL Action Gate provides durable reservation, idempotency, and
finality. The browser demo uses local PostgreSQL; the final GCP sandbox proof
used Cloud Run and Cloud SQL to reconcile a deliberate
unknown-after-acceptance result with zero redispatch. A React and TypeScript UI
keeps its tracked cloud replay separate from the local execution sandbox.

Institutional evidence also does not have to arrive in one synchronous prompt.
The local durability demo persists a case, exits one Python process, and resumes
the same PostgreSQL head and transcript in another when an authorized source
responds later. The pause is simulated; this proof does not claim Cloud SQL,
actual elapsed days, or browser persistence.

This is a Fortified Enterprise Fleet: the Fleet Catalog discovers and routes
source-owned institutional agents, but discovery grants no authority. Source
agents run under isolated cloud identities; Q-12 independently establishes
institutional authority; and durable case and Action Gate records preserve
control semantics across retries and races.

The hero decision path uses bounded enumeration. Z3 is a differential checking
oracle, not the production decider.

## Google AI Models / Google Cloud

Model tier follows trust tier in this integration. Gemma 4 handles the
unverified human narrative in the optional local `--live` path only — it was
not part of the verified Stage-90 cloud execution or the final GCP Action Gate
proof — and its candidate still passes deterministic claim validation and has
no signature, source authority, Q-12 path, or decision power. Gemini 3.7 Flash
handles institutional source material through Vertex AI; validated and signed
source attestations then face Q-12. Deterministic
MUSTER controls own authority, policy, consequence evaluation, and execution
eligibility.

Site-A demonstrates genuine multimodal interpretation. Its authorized agent
retrieves `attendance-board-sat.png` and `gate-log-sat.txt`, sends raw PNG bytes
through ADK `inline_data` with the text, and asks Gemini 3.7 Flash at the Vertex
AI `global` location for structured candidate facts. Deterministic code checks
the candidates before the source signs them.

The MUSTER Control Plane cannot read that raw Site-A evidence: the verified
cloud run received a real IAM HTTP 403. Only the authorized Site Agent retrieves
it. Raw evidence never reaches the Control Plane, although the source agent may
send necessary evidence content to Vertex AI for interpretation. Only
validated, signed narrow attestations enter MUSTER.

Gemini provides multimodal interpretation; MUSTER provides authority, policy,
reproducibility, and execution controls. Both are essential and separate.

## What Makes It Different

MUSTER acquires evidence according to consequences, not curiosity. Procurement
PO-4821 makes the capability concrete: the same uncertainty is 97–100 units.
Fixed price produces one reachable consequence, INR 63,000, so acquisition
stops. Per-unit pricing produces four reachable consequences, so MUSTER
requests the exact quantity from an authorized warehouse source. **The policy
changed; the kernel did not.** This is a local deterministic proof, not a cloud
claim.

## Challenges

The hardest work was separating signatures from institutional authority,
preserving correlated facts while minimizing evidence, enforcing IAM isolation,
and defining reproducible execution under races and post-dispatch uncertainty.
The Action Gate binds authority to an exact action and never automatically
redispatches an uncertain outcome.

## Accomplishments

- Deployed real Site and Employer agents on Google Cloud.
- Interpreted a genuine PNG plus text with Gemini 3.7 Flash.
- Integrated the additional Google AI model Gemma 4
  (`gemma-4-26b-a4b-it`) for optional hosted Worker claim
  intake through the Gemini Developer API while preserving an unsigned,
  institutionally inert result.
- Captured a real Control Plane IAM 403 against private Site-A evidence.
- Admitted signed attestations through Q-12 institutional authority checks.
- Reached and rebuilt a deterministic `INVARIANT` result while exact duration
  remained unresolved.
- Built a durable PostgreSQL Action Gate with concurrency, idempotency and
  finality controls, then verified the sandbox unknown-after-acceptance and
  reconciliation sequence on Cloud Run + Cloud SQL; no real funds transferred.
- Demonstrated the same kernel across workforce and procurement policies.
- Collected 7,706 Python tests, with **0 failures in either environment
  recorded**. How many of them run is a property of the machine: many suites
  drive the deployment shell scripts through a real `bash` and skip where no
  POSIX shell answers a probe, so the counts are reported per environment
  rather than as one number. Two complete runs on Windows 11 / Python 3.12,
  with no database DSN and no cloud credentials: **7,318 passed / 388 skipped**
  with a POSIX shell on `PATH` (Git Bash), and **7,210 passed / 496 skipped**
  without one (PowerShell) — a difference of exactly the 108 shell-driven
  tests. The UI adds 119 passing Vitest tests. **No Linux run is recorded yet
  and none is claimed**; a minimal GitHub Actions workflow runs ruff, mypy, all
  three import-linter configurations, pytest and the UI's three commands on
  `ubuntu-24.04`, and is the intended source of a supported-platform number
  once GitHub has run it.

## What We Learned

AI interpretation and institutional authority are separate concepts. Better
autonomy sometimes means recognizing that more evidence cannot change the
action. And execution needs stronger semantics than reasoning: exact action
binding, durable state, and honest treatment of uncertain finality.

## What's Next

Future work can add enterprise source adapters, richer policy bundles,
production system integrations, and more institutional domains. The verified
managed-cloud Action Gate remains a synthetic sandbox; any production executor
integration would have to preserve its deterministic boundary and
reconciliation-first finality model.

## Try It Out

- Repository: <https://github.com/satish9177/muster>
- Hosted replay: [public read-only verified replay](https://muster-judge-replay-867434431401.asia-south1.run.app) — not live telemetry, with no backend or mutation endpoint
- Demo video: [to be added before submission]
- Architecture image: [PNG](assets/muster-architecture.png) ·
  [full-size SVG](assets/muster-architecture.svg)

## Built With

- Python
- Google ADK
- Gemma 4 (`gemma-4-26b-a4b-it`)
- Gemini 3.7 Flash
- Vertex AI
- Cloud Run
- Cloud Storage
- IAM
- Secret Manager
- Artifact Registry
- Cloud Build
- PostgreSQL
- React
- TypeScript
