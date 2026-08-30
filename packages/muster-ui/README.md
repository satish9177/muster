# MUSTER hero UI

The UI-1 case viewer is a local TypeScript/React application. It renders a
typed platform-facing read model and never imports, duplicates, or evaluates
kernel policy semantics.

The viewer first requests the tracked, sanitized Stage-90-generated
`public/cases/ravi-cloud-execution.json` artifact and adapts it into the UI-1
read model. A verified artifact is labeled `verified-cloud-execution` and is
always shown as a replay, never live telemetry.

Only a 404 on that preferred artifact activates the bundled Ravi payload. The
fallback is explicitly labeled `curated-example`; a present but malformed
cloud artifact fails closed instead of silently falling back.

## Two builds, and the safe one is the default

`npm run build` produces the **replay-only judge build**: static, GET-only, no
`/api/demo` request, no Action Gate mutation control, no database and no
credential. `npm run dev` keeps the local PostgreSQL Action Gate controls.
The mode is resolved once in `src/data/runtimeMode.ts` and fails closed — a
production bundle is replay-only unless it is built with
`VITE_MUSTER_LOCAL_GATE=true` — and it is enforced in four places: the client
call site in `App.tsx`, the control in `CaseHeader.tsx`, the HTTP request in
`HttpActionGateClient` itself, and the Action view's body, which in a
replay-only build is the verified cloud proof alone. The local Action Gate
panel is a developer surface and renders only in the developer build; putting
a notice about it under the cloud receipt would place a second, local execution
surface on the one screen whose subject is the verified cloud execution.

## The final Gate proof

`public/cases/ravi-cloud-gate-proof.json` (`muster.action-gate-proof/v1`) is the
tracked, sanitized record of the final Google Cloud unknown-after-acceptance and
reconciliation proof: five named Cloud Run executions, one dispatch, zero
redispatch, one surviving synthetic transfer. `CloudGateProof.tsx` renders it as
a plain-English timeline with the technical vocabulary as secondary text, and
`gateProofReadModel.ts` refuses any record that fails to assert sandbox-only, no
real funds, not live telemetry, and no Cloud Run process death.

It is a **different document** from `ravi-cloud-execution.json`, which is the
earlier analysis-only run and still correctly reports `NOT_EXECUTED`. Neither
artifact is ever reinterpreted as the other.

```powershell
npm.cmd install
..\..\.venv\Scripts\python.exe ..\..\demo\action_gate_api.py
npm.cmd run dev
```

The first process is a loopback-only, PostgreSQL-backed local sandbox Action
Gate. The browser sends an empty POST to an opaque proposal-reference URL; it
never submits recipient, amount, currency, or action kind. This local
deterministic sandbox execution path is labeled separately from the verified
Google Cloud execution replay. No real funds are transferred.

`ravi-cloud-execution.json` proves the observed model, IAM result, candidate
facts, Q-12 checks, and deterministic result from the tracked analysis-only
Stage-90 cloud execution. `ravi-evidence-proof.json` is a separate
implementation audit: it proves the committed request shape and modalities and
is not runtime telemetry.
The Worker Agent path accepts text and includes Gemini interpretation, but that
agent was not rerun in the tracked analysis-only Stage-90 cloud hero.

Validation:

```powershell
npm.cmd test
npm.cmd run build
```
