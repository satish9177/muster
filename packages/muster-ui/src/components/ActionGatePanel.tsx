import { AlertTriangle, Check, CircleDashed, ShieldCheck, X } from "lucide-react";

import type { ActionGateReadModel, GateLifecycleStep } from "../data/actionGate";

interface ActionGatePanelProps {
  gate: ActionGateReadModel | null;
  unavailableReason: string | null;
}

export function ActionGatePanel({ gate, unavailableReason }: ActionGatePanelProps) {
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

function GateOutcome({ gate }: { gate: ActionGateReadModel }) {
  if (gate.phase === "UNCERTAIN" || gate.phase === "DISPATCHED") {
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
