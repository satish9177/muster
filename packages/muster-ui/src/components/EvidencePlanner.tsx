import { Check, Circle, CircleDot, Target } from "lucide-react";
import { useEffect, useState } from "react";

import { evidencePlanClient } from "../data/evidencePlanClient";
import type { EvidencePlanReadModel } from "../data/evidencePlanReadModel";

export function EvidencePlanner() {
  const [model, setModel] = useState<EvidencePlanReadModel | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    evidencePlanClient.load(controller.signal).then(setModel).catch((reason: unknown) => {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : "Evidence plan unavailable");
    });
    return () => controller.abort();
  }, []);

  if (error) return <main className="planner-state">{error}</main>;
  if (!model) return <main className="planner-state">Loading evidence plan…</main>;

  return (
    <main className="planner-workspace">
      <section className="planner-heading">
        <div>
          <span className="section-label">CONSEQUENCE-SENSITIVE EVIDENCE PLAN</span>
          <h2>Ask only for facts that can still change the action.</h2>
        </div>
        <span className="provenance-chip">{model.provenance.label}</span>
      </section>

      <div className="planner-grid">
        <section className="planner-panel required-panel">
          <header><Check size={18} aria-hidden="true" /><div><span>REQUIRED / RESOLVED</span><strong>Evidence that mattered</strong></div></header>
          <div className="plan-list">
            {model.required_resolved.map((item) => (
              <article key={item.proposition.display}>
                <Check size={17} aria-hidden="true" />
                <div>
                  <strong>{item.label}</strong>
                  <code>{item.proposition.display}</code>
                  <span>{item.requirement}</span>
                  <span>{item.established}</span>
                  <small>{item.reason}</small>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="planner-panel stop-panel">
          <header><Circle size={18} aria-hidden="true" /><div><span>NOT REQUIRED</span><strong>Why MUSTER stopped</strong></div></header>
          {model.not_required.map((item) => (
            <article className="not-required-row" key={item.label}>
              <CircleDot size={18} aria-hidden="true" />
              <div><strong>{item.label}</strong><span>{item.status.replace("_", " ")}</span><p>{item.reason}</p></div>
            </article>
          ))}
          <p className="stop-explanation">{model.summary.explanation} Threshold evidence was acquired; only the exact count was unnecessary.</p>
        </section>

        <aside className="planner-summary">
          <Target size={20} aria-hidden="true" />
          <span>REACHABLE CONSEQUENTIAL ACTIONS</span>
          <strong className="action-count">{model.summary.reachable_action_count}</strong>
          <dl>
            <div><dt>Outcome</dt><dd>{model.summary.outcome}</dd></div>
            <div><dt>Exact duration</dt><dd>{model.summary.exact_duration_status}</dd></div>
            <div><dt>Recipient</dt><dd>{model.summary.action.fields.recipient?.display}</dd></div>
            <div><dt>Corrected total</dt><dd>{model.summary.action.fields.amount?.display}</dd></div>
          </dl>
        </aside>
      </div>
    </main>
  );
}
