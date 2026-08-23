# MUSTER

> **When records disagree, MUSTER proves only what matters — and acts only on what can be proved.**

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

## How We Built It

The Python kernel and control plane integrate with Google ADK source agents and
Gemini 3.7 Flash through Vertex AI. Cloud Run hosts the agents in
`asia-south1`; Cloud Storage holds synthetic evidence; IAM isolates identities;
and Secret Manager holds signing keys.

A local PostgreSQL Action Gate provides durable reservation, idempotency, and
finality. A React and TypeScript UI separates verified cloud replay from the
local execution sandbox.

This is a Fortified Enterprise Fleet: the Fleet Catalog discovers and routes
source-owned institutional agents, but discovery grants no authority. Source
agents run under isolated cloud identities; Q-12 independently establishes
institutional authority; and durable case and Action Gate records preserve
control semantics across retries and races.

The hero decision path uses bounded enumeration. Z3 is a differential checking
oracle, not the production decider.

## Gemini / Google Cloud

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
- Captured a real Control Plane IAM 403 against private Site-A evidence.
- Admitted signed attestations through Q-12 institutional authority checks.
- Reached and rebuilt a deterministic `INVARIANT` result while exact duration
  remained unresolved.
- Built a durable local PostgreSQL Action Gate with concurrency, idempotency,
  and finality controls; the sandbox transfers no real funds.
- Demonstrated the same kernel across workforce and procurement policies.
- Collected 2,345 tests; the latest verified full suite reports 2,065 passed,
  280 environment-dependent skips, and 0 failures.

## What We Learned

AI interpretation and institutional authority are separate concepts. Better
autonomy sometimes means recognizing that more evidence cannot change the
action. And execution needs stronger semantics than reasoning: exact action
binding, durable state, and honest treatment of uncertain finality.

## What's Next

Future work can add enterprise source adapters, richer policy bundles,
production system integrations, and more institutional domains. The local
Action Gate can move to a managed durable cloud deployment while preserving its
deterministic boundary and reconciliation-first finality model.

## Try It Out

- Repository: <https://github.com/satish9177/muster>
- Demo video: [to be added before submission]
- Architecture image: [PNG](assets/muster-architecture.png) ·
  [full-size SVG](assets/muster-architecture.svg)

## Built With

- Python
- Google ADK
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
