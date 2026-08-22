import { CircleDotDashed, LockKeyhole, RadioTower } from "lucide-react";

import type { HeroCaseViewModel } from "../data/readModel";

interface CaseHeaderProps {
  model: HeroCaseViewModel;
}

export function CaseHeader({ model }: CaseHeaderProps) {
  return (
    <>
      <header className="app-bar">
        <div className="brand" aria-label="MUSTER case control">
          <span className="brand-mark" aria-hidden="true">
            M
          </span>
          <span className="brand-name">MUSTER</span>
          <span className="brand-section">CASE CONTROL</span>
        </div>
        <div className="replay-state" aria-label={model.provenance.description}>
          <RadioTower size={14} aria-hidden="true" />
          <span>{model.provenance.label}</span>
          <span className="replay-separator" aria-hidden="true" />
          <strong>NOT LIVE</strong>
        </div>
      </header>

      <section className="case-header" aria-labelledby="case-title">
        <div className="case-identity">
          <div className="case-kicker">
            <span>CASE {model.id}</span>
            <span className="case-dot" aria-hidden="true" />
            <span>WORKFORCE / SHIFT PAY</span>
          </div>
          <h1 id="case-title">{model.title}</h1>
          <div className="policy-line">
            <LockKeyhole size={14} aria-hidden="true" />
            <span className="policy-label">PINNED POLICY</span>
            <code>{model.pinnedPolicy}</code>
            <span className="policy-version">{model.policyVersion}</span>
          </div>
        </div>

        <div className="case-result" aria-label="Proposed invariant result">
          <div className="result-statuses">
            <span className="status-chip proposed">{model.status}</span>
            <span className="status-chip invariant">
              <CircleDotDashed size={13} aria-hidden="true" />
              {model.outcome}
            </span>
          </div>
          <div className="result-action">
            <div>
              <span className="result-label">PROPOSED PAYMENT</span>
              <strong>{model.action.amount}</strong>
            </div>
            <div className="result-recipient">
              <span>PAY</span>
              <strong>{model.action.recipient}</strong>
            </div>
          </div>
          <div className="gate-state">
            <span className="gate-indicator" aria-hidden="true" />
            Action Gate pending · nothing executed
          </div>
        </div>
      </section>
    </>
  );
}
