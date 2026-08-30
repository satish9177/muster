import { AlertTriangle, Check, CircleDashed, FileLock2, ShieldCheck, X } from "lucide-react";

import type { ActionGateReadModel, GateLifecycleStep } from "../data/actionGate";
import { reconciliationRequired, wasReconciled } from "../data/actionGate";
import { runtimeMode, type RuntimeMode } from "../data/runtimeMode";

interface ActionGatePanelProps {
  gate: ActionGateReadModel | null;
  unavailableReason: string | null;
  /** Injectable so both builds' surfaces are reachable from one test run. */
  mode?: RuntimeMode;
}

export function ActionGatePanel({
  gate,
  unavailableReason,
  mode = runtimeMode,
}: ActionGatePanelProps) {
  //  In the hosted judge build there is no local Action Gate to be unavailable.
  //  Reporting "NOT EXECUTED / sandbox unavailable" there would be a broken
  //  promise dressed as a result: it reads as a failed execution of the case,
  //  when in fact nothing was ever meant to execute in this bundle. Say what is
  //  true instead, and point at the proof that actually applies.
  if (mode.replayOnly) {
    return (
      <section className="action-gate-panel replay-only" aria-label="Local Action Gate availability">
        <div className="gate-provenance">
          <span className="section-label">LOCAL ACTION GATE</span>
          <strong>{mode.label}</strong>
          <span>No mutation endpoint is exposed.</span>
        </div>
        <div className="gate-replay-note">
          <FileLock2 size={17} aria-hidden="true" />
          <span>
            <strong>NOTHING TO EXECUTE HERE</strong>
            The interactive PostgreSQL Action Gate is a local developer demo. See the
            verified Google Cloud Action proof in this tab; it is complete and needs no
            backend.
          </span>
        </div>
      </section>
    );
  }

  return (
    <section className="action-gate-panel" aria-label="Action Gate execution proof">
      <div className="gate-provenance">
        <span className="section-label">ACTION EXECUTION</span>
        <strong>POSTGRESQL-BACKED LOCAL SANDBOX ACTION GATE</strong>
        <span>Local deterministic sandbox execution · No real funds transferred</span>
      </div>

      {gate ? (
        <>
          <ol className="gate-lifecycle" aria-label="Durable Action Gate lifecycle">
            {gate.lifecycle.map((step) => (
              <GateStep key={step} step={step} current={step === gate.lifecycle.at(-1)} />
            ))}
          </ol>
          <GateOutcome gate={gate} />
          <GateReconciliation gate={gate} />
        </>
      ) : (
        <div className="gate-unavailable">
          <CircleDashed size={17} aria-hidden="true" />
          <span>
            <strong>NOT EXECUTED</strong>
            {unavailableReason ?? "Connecting to local sandbox Action Gate…"}
          </span>
        </div>
      )}
    </section>
  );
}

function GateStep({ step, current }: { step: GateLifecycleStep; current: boolean }) {
  return (
    <li className={`gate-step ${current ? "current" : "complete"}`}>
      <span className="gate-step-mark" aria-hidden="true">
        {current ? <ShieldCheck size={12} /> : <Check size={11} />}
      </span>
      <span>{step}</span>
    </li>
  );
}

/**
 * Read-only provenance for an outcome that was established by observation.
 *
 * There is deliberately no control here: reconciliation is something an
 * operator invokes elsewhere, and this surface only reports that it happened.
 */
function GateReconciliation({ gate }: { gate: ActionGateReadModel }) {
  if (!wasReconciled(gate)) return null;
  return (
    <p className="gate-reconciliation">
      <span className="section-label">RECONCILED</span>
      <span>
        Outcome established by inspecting the executor, from {gate.reconciledFrom}. No
        redispatch occurred.
      </span>
    </p>
  );
}

function GateOutcome({ gate }: { gate: ActionGateReadModel }) {
  if (reconciliationRequired(gate)) {
    return (
      <div className="gate-outcome uncertain">
        <AlertTriangle size={17} aria-hidden="true" />
        <span>
          <strong>UNCERTAIN</strong>
          Automatic retry disabled · reconciliation required
        </span>
      </div>
    );
  }
  if (gate.phase === "FAILED") {
    return (
      <div className="gate-outcome failed">
        <X size={17} aria-hidden="true" />
        <span>
          <strong>FAILED</strong>
          Definitely not executed
        </span>
      </div>
    );
  }
  if (gate.phase === "EXECUTED") {
    return (
      <div className="gate-outcome executed">
        <Check size={17} aria-hidden="true" />
        <span>
          <strong>EXECUTED ONCE · SANDBOX</strong>
          <code>{gate.externalReference}</code>
          {gate.existingConfirmationReturned && <em>Existing confirmation · no second dispatch</em>}
        </span>
      </div>
    );
  }
  return (
    <div className="gate-outcome authorized">
      <ShieldCheck size={17} aria-hidden="true" />
      <span>
        <strong>{gate.phase === "AUTHORIZED" ? "NOT EXECUTED" : gate.phase}</strong>
        {gate.phase === "AUTHORIZED"
          ? "AUTHORIZED · GATE ELIGIBLE · sandbox only"
          : "Proposal identity verified · sandbox only"}
      </span>
    </div>
  );
}
