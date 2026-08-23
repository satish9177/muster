# MUSTER hero UI

The UI-1 case viewer is a local TypeScript/React application. It renders a
typed platform-facing read model and never imports, duplicates, or evaluates
kernel policy semantics.

The viewer first requests the ignored, Stage-90-generated
`public/cases/ravi-cloud-execution.json` artifact and adapts it into the UI-1
read model. A verified artifact is labeled `verified-cloud-execution` and is
always shown as a replay, never live telemetry.

Only a 404 on that preferred artifact activates the bundled Ravi payload. The
fallback is explicitly labeled `curated-example`; a present but malformed
cloud artifact fails closed instead of silently falling back.

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
facts, Q-12 checks, and deterministic result from the verified Stage-90 cloud
execution. `ravi-evidence-proof.json` is a separate implementation audit: it
proves the committed request shape and modalities and is not runtime telemetry.
The Worker Agent path accepts text and includes Gemini interpretation, but that
agent was not rerun in the verified Stage-90 cloud hero.

Validation:

```powershell
npm.cmd test
npm.cmd run build
```
