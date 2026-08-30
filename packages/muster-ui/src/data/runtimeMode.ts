/**
 * Which of the two builds this bundle is, decided once and fail-closed.
 *
 * There are exactly two: the **developer build**, which may talk to a local
 * PostgreSQL Action Gate over `/api/demo` and offers the mutation control that
 * demo needs; and the **replay-only judge build**, which is static, GET-only,
 * has no backend, no database, no secret and no mutation endpoint, and is the
 * only shape that is safe to host publicly.
 *
 * The default is the safe one. A production bundle is replay-only *unless*
 * someone deliberately builds it with `VITE_MUSTER_LOCAL_GATE=true`, so an
 * ordinary `npm run build` — the command a hosted deployment will run — can
 * never accidentally ship a mutation control. Getting this backwards is the
 * failure that matters: a judge build that renders an execute button either
 * offers to mutate something, or shows a broken "sandbox unavailable" error
 * for a backend that was never meant to exist. Both are lies about the system.
 *
 * `import.meta.env.DEV` keeps `npm run dev` working as it does today without
 * anyone having to remember a flag.
 */
export interface RuntimeMode {
  /** True when no mutation endpoint exists and none may be attempted. */
  readonly replayOnly: boolean;
  /** The persistent banner text. Never implies a live stream. */
  readonly label: string;
}

const REPLAY_ONLY: RuntimeMode = {
  replayOnly: true,
  label: "REPLAY-ONLY JUDGE BUILD",
};

const LOCAL_GATE: RuntimeMode = {
  replayOnly: false,
  label: "LOCAL DEVELOPER BUILD",
};

export function resolveRuntimeMode(
  environment: { DEV?: boolean; VITE_MUSTER_LOCAL_GATE?: string } = import.meta.env,
): RuntimeMode {
  if (environment.VITE_MUSTER_LOCAL_GATE === "true") return LOCAL_GATE;
  if (environment.VITE_MUSTER_LOCAL_GATE === "false") return REPLAY_ONLY;
  return environment.DEV === true ? LOCAL_GATE : REPLAY_ONLY;
}

export const runtimeMode: RuntimeMode = resolveRuntimeMode();
