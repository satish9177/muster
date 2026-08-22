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

The first process is a loopback-only local demo API over the real deterministic
Action Gate and synthetic sandbox executor. The browser sends an empty POST to
an opaque proposal-reference URL; it never submits recipient, amount, currency,
or action kind. This local action path is labeled separately from the verified
Google Cloud evidence/agent replay. No real funds are transferred.

Validation:

```powershell
npm.cmd test
npm.cmd run build
```
