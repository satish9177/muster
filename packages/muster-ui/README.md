# MUSTER hero UI

The UI-1 case viewer is a local TypeScript/React application. It renders a
typed platform-facing read model and never imports, duplicates, or evaluates
kernel policy semantics.

The bundled Ravi payload is labeled `verified-replay`. It is a curated view of
the existing Milestone-F worked-run contract, not live Cloud Run telemetry and
not a saved execution capture. `captured-replay` and `live` modes are reserved
by the adapter for a later endpoint; the adapter refuses to label an
un-timestamped payload as live.

```powershell
npm.cmd install
npm.cmd run dev
```

Validation:

```powershell
npm.cmd test
npm.cmd run build
```
