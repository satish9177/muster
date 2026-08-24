import { Check, Database, Pause, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import { asyncDurabilityClient } from "../data/asyncClient";
import type { AsyncDurabilityReadModel } from "../data/asyncReadModel";

export function DurableCaseHistory() {
  const [model, setModel] = useState<AsyncDurabilityReadModel | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    asyncDurabilityClient.load(controller.signal).then(setModel).catch((reason: unknown) => {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : "Durability proof unavailable");
    });
    return () => controller.abort();
  }, []);

  if (error) return <main className="planner-state">{error}</main>;
  if (!model) return <main className="planner-state">Loading durability proof…</main>;

  const [employer, resumed] = model.events;
  return (
    <main className="durable-workspace">
      <section className="durable-heading">
        <div>
          <span className="section-label">DURABLE CASE HISTORY</span>
          <h2>Same case · resumed after restart</h2>
          <p>Institutional evidence arrived in separate processes; PostgreSQL preserved the case context.</p>
        </div>
        <div className="durable-proof-label"><Database size={17} aria-hidden="true" /><span>{model.provenance.label}<small>{model.provenance.environment} · NOT CLOUD EXECUTION</small></span></div>
      </section>

      <section className="durable-flow">
        <article className="durable-event">
          <span className="event-time">{employer.label}</span>
          <div className="event-icon"><Database size={19} aria-hidden="true" /></div>
          <div><span>EMPLOYER EVIDENCE ARRIVES</span><h3>{evidenceDisplay(employer.delivered[0])}</h3><p><Check size={14} /> Q-12 passed · durable revision stored · waiting for evidence</p></div>
          <dl><div><dt>Process</dt><dd>{employer.process_id}</dd></div><div><dt>Revision</dt><dd>{employer.state.head.revision_number}</dd></div><div><dt>Head</dt><dd>{shortDigest(employer.state.head.revision_digest)}</dd></div></dl>
        </article>

        <div className="async-gap"><Pause size={15} aria-hidden="true" /><span>DIFFERENT PROCESS / RESTART</span><strong>SIMULATED ASYNC GAP · revision {employer.state.head.revision_number} → {resumed.state.head.revision_number}</strong></div>

        <article className="durable-event resumed-event">
          <span className="event-time">LATER</span>
          <div className="event-icon"><RefreshCw size={19} aria-hidden="true" /></div>
          <div><span>SITE EVIDENCE ARRIVES · SAME CASE RESUMED</span><h3>{resumed.delivered.map(evidenceDisplay).join(" · ")}</h3><p><Check size={14} /> Q-12 passed · prior employer evidence preserved</p></div>
          <dl><div><dt>Process</dt><dd>{resumed.process_id}</dd></div><div><dt>Revision</dt><dd>{resumed.state.head.revision_number}</dd></div><div><dt>Transcript</dt><dd>{shortDigest(resumed.state.head.transcript_prefix_digest)}</dd></div></dl>
        </article>
      </section>

      <section className="durable-result">
        <div><span>CONTINUITY PROOF</span><strong>SAME CASE</strong><small>{model.case.tenant_id} / {model.case.case_id}</small></div>
        <div><span>FINAL RESULT</span><strong>{employer.state.outcome} → {model.result.outcome}</strong><small>Exact duration {model.result.exact_duration_status}</small></div>
        <div><span>CORRECTED TOTAL</span><strong>{model.result.action.amount.display}</strong><small>{model.result.execution.replace("_", " ")}</small></div>
      </section>
    </main>
  );
}

function shortDigest(digest: string): string {
  return `${digest.slice(0, 10)}…`;
}

function evidenceDisplay(evidence: { proposition: { display: string }; relation: { display: string } } | undefined): string {
  return evidence ? `${evidence.proposition.display} ${evidence.relation.display}` : "Authorized evidence";
}
