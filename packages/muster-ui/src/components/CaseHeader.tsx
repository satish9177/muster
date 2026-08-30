import { CircleDotDashed, LockKeyhole, Play, RadioTower } from "lucide-react";

import { gateActionLabel, mayInvokeGate, type ActionGateReadModel } from "../data/actionGate";
import { kernelOutcomeTerm } from "../data/plainLanguage";
import type { HeroCaseViewModel } from "../data/readModel";
import { runtimeMode } from "../data/runtimeMode";

interface CaseHeaderProps {
  model: HeroCaseViewModel;
  gate: ActionGateReadModel | null;
  executing: boolean;
  onExecute: () => void;
}

export function CaseHeader({ model, gate, executing, onExecute }: CaseHeaderProps) {
  const outcome = kernelOutcomeTerm(model.outcome);
  return (
      <section className="case-header" aria-labelledby="case-title">
        <div className="case-identity">
          <div className="case-kicker">
            <span>CASE {model.id}</span>
            <span className="case-dot" aria-hidden="true" />
            <span>WORKFORCE / SHIFT PAY</span>
          </div>
          <h1 id="case-title">{model.title}</h1>
          <p className="case-question">
            Can {model.action.amount} be safely authorized without the central Control Plane
            ever reading {model.action.recipient}&rsquo;s raw site records?
          </p>
          <div className="policy-line">
            <LockKeyhole size={14} aria-hidden="true" />
            <span className="policy-label">PINNED POLICY</span>
            <code>{model.pinnedPolicy}</code>
            <span className="policy-version">{model.policyVersion}</span>
          </div>
          <div className="case-replay-state" aria-label={model.provenance.description}>
            <RadioTower size={12} aria-hidden="true" /> {model.provenance.label} <b>NOT LIVE</b>
          </div>
        </div>

        <div className="case-result" aria-label="Proposed invariant result">
          <div className="result-statuses">
            <span className="status-chip proposed">{model.status}</span>
            <span className="status-chip invariant" title={outcome.technical}>
              <CircleDotDashed size={13} aria-hidden="true" />
              {outcome.plain}
              <small>{outcome.technical}</small>
            </span>
          </div>
          <div className="result-action">
            <div>
              <span className="result-label">PROPOSED PAYMENT · CORRECTED WEEKLY TOTAL</span>
              <strong>{model.action.amount}</strong>
            </div>
            <div className="result-recipient">
              <span>PAY</span>
              <strong>{model.action.recipient}</strong>
            </div>
          </div>
          {/*
            The mutation control belongs to the local developer demo and to
            nothing else. In the replay-only judge build there is no endpoint
            behind it, so it is absent rather than disabled: a greyed-out
            "Sandbox unavailable" button reads as a system that is broken,
            when what is true is that this build deliberately has no backend.
          */}
          {runtimeMode.replayOnly ? (
            <div className="gate-state">
              <span className="gate-indicator" aria-hidden="true" />
              LOCAL SANDBOX NOT PART OF THIS BUILD · see the verified Google Cloud proof
            </div>
          ) : (
            <>
              <div className="gate-state">
                <span className="gate-indicator" aria-hidden="true" />
                {gate?.phase === "EXECUTED"
                  ? "EXECUTED ONCE · sandbox confirmation is durable"
                  : "NOT EXECUTED · no real funds transferred"}
              </div>
              <button
                type="button"
                className="execute-action"
                onClick={onExecute}
                disabled={!gate || executing || !mayInvokeGate(gate)}
              >
                <Play size={13} fill="currentColor" aria-hidden="true" />
                {executing
                  ? "Executing exact proposal…"
                  : gate
                    ? gateActionLabel(gate)
                    : "Sandbox unavailable"}
              </button>
            </>
          )}
        </div>
      </section>
  );
}
