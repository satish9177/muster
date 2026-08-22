import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CircleDotDashed,
  FileCheck2,
  LockKeyhole,
  RefreshCcw,
  Scale,
  Warehouse,
} from "lucide-react";
import { useEffect, useState } from "react";

import { procurementCaseClient } from "../data/procurementClient";
import type {
  ProcurementCaseViewModel,
  ProcurementPolicyKey,
} from "../data/procurementReadModel";

export function ProcurementCase() {
  const [policy, setPolicy] = useState<ProcurementPolicyKey>("FIXED_TOLERANCE");
  const [model, setModel] = useState<ProcurementCaseViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    procurementCaseClient
      .load(policy, controller.signal)
      .then(setModel)
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Procurement case unavailable");
      });
    return () => controller.abort();
  }, [policy, reloadKey]);

  if (error) {
    return (
      <main className="load-state error-state">
        <AlertTriangle size={28} aria-hidden="true" />
        <h1>Procurement proof unavailable</h1>
        <p>{error}</p>
        <button type="button" onClick={() => setReloadKey((key) => key + 1)}>
          <RefreshCcw size={15} aria-hidden="true" /> Retry
        </button>
      </main>
    );
  }

  if (!model || model.policy.key !== policy) {
    return (
      <main className="load-state" aria-label="Loading procurement case">
        <span className="loading-mark" aria-hidden="true">M</span>
        <p>Evaluating pinned procurement policy…</p>
      </main>
    );
  }

  const invariant = model.result.outcome === "INVARIANT";
  return (
    <div className="procurement-shell">
      <header className="app-bar procurement-bar">
        <div className="brand" aria-label="MUSTER procurement proof">
          <span className="brand-mark" aria-hidden="true">M</span>
          <span className="brand-name">MUSTER</span>
          <span className="brand-section">CASE CONTROL</span>
        </div>
        <div className="replay-state">
          <Scale size={14} aria-hidden="true" />
          <span>DETERMINISTIC CROSS-DOMAIN PROOF</span>
        </div>
      </header>

      <section className="procurement-heading">
        <div>
          <span className="case-kicker">PROCUREMENT / SUPPLIER DELIVERY</span>
          <h1>{model.case.po_id} <span>·</span> {model.case.title}</h1>
          <p>One unresolved fact. Two pinned policies. The action decides whether proof is needed.</p>
        </div>
        <div className="kernel-note">
          <Boxes size={18} aria-hidden="true" />
          <span><strong>Same MUSTER kernel</strong>Same authority and admissibility machinery</span>
        </div>
      </section>

      <main className="procurement-workspace">
        <section className="proc-card source-section" aria-labelledby="source-heading">
          <div className="proc-card-heading">
            <span className="section-label">SAME SOURCE EVIDENCE</span>
            <h2 id="source-heading">Quantity records</h2>
          </div>
          <div className="source-cards">
            {model.sources.map((source) => (
              <article className="source-card" key={source.source_class}>
                {source.relation === "CLAIM" ? (
                  <FileCheck2 size={19} aria-hidden="true" />
                ) : (
                  <Warehouse size={19} aria-hidden="true" />
                )}
                <div>
                  <span>{source.label}</span>
                  <strong>
                    {source.quantity} units {source.relation === "CLAIM" ? "claimed" : "confirmed"}
                  </strong>
                </div>
                <small>
                  {source.relation === "CLAIM"
                    ? "CLAIM ONLY · NOT AUTHORITATIVE"
                    : "LOWER BOUND · NOT FINAL QUANTITY"}
                </small>
              </article>
            ))}
          </div>
          <div className="disagreement-callout">
            <AlertTriangle size={17} aria-hidden="true" />
            <div>
              <strong>AUTHORITATIVE RANGE · 97–100 UNITS</strong>
              <span>97 confirmed is a closed lower bound; exact delivered quantity remains unresolved</span>
            </div>
          </div>
          <dl className="source-facts">
            <div><dt>Tenant</dt><dd>{model.case.tenant_id}</dd></div>
            <div><dt>Authority scope</dt><dd>PURCHASE_ORDER / {model.case.po_id}</dd></div>
            <div>
              <dt>Admissible envelope</dt>
              <dd>Warehouse floor {model.uncertainty.lower_bound.quantity} · PO ceiling {model.uncertainty.upper_bound.quantity}</dd>
            </div>
          </dl>
        </section>

        <section className="proc-card policy-section" aria-labelledby="policy-heading">
          <div className="proc-card-heading">
            <span className="section-label">PINNED POLICY CONTROL</span>
            <h2 id="policy-heading">Change policy only</h2>
          </div>
          <div className="policy-switch" role="group" aria-label="Procurement policy">
            <button
              type="button"
              className={policy === "FIXED_TOLERANCE" ? "active" : ""}
              onClick={() => setPolicy("FIXED_TOLERANCE")}
            >Fixed contract</button>
            <button
              type="button"
              className={policy === "PER_UNIT" ? "active" : ""}
              onClick={() => setPolicy("PER_UNIT")}
            >Per-unit contract</button>
          </div>
          <div className="policy-definition">
            <LockKeyhole size={16} aria-hidden="true" />
            <div>
              <span>POLICY</span>
              <strong>
                {policy === "FIXED_TOLERANCE"
                  ? `Acceptable if quantity ≥ ${model.policy.acceptance_minimum}`
                  : `${model.policy.perUnitRate} / unit`}
              </strong>
              <code>{model.policy.policy_id} · {model.policy.version}</code>
            </div>
          </div>
          <div className="alternative-list">
            {model.alternatives.map((alternative) => (
              <div key={alternative.quantity}>
                <span>{alternative.quantity} units</span>
                <ArrowRight size={15} aria-hidden="true" />
                <strong>{alternative.amount}</strong>
              </div>
            ))}
          </div>
          <p className="contract-note">
            {policy === "FIXED_TOLERANCE"
              ? `Fixed payment ${model.policy.fixedAmount}`
              : `Rate pinned at ${model.policy.perUnitRate} per unit`}
          </p>
          <code className="manifest-pin" title={model.policy.manifest_digest}>
            MANIFEST {model.policy.manifest_digest.slice(0, 16)}…
          </code>
        </section>

        <section className={`proc-card result-section ${invariant ? "is-invariant" : "is-divergent"}`} aria-labelledby="result-heading">
          <div className="proc-card-heading">
            <span className="section-label">MECHANICALLY DERIVED RESULT</span>
            <h2 id="result-heading">Action sensitivity</h2>
          </div>
          <div className="proc-result">
            {invariant ? <CheckCircle2 size={26} aria-hidden="true" /> : <CircleDotDashed size={26} aria-hidden="true" />}
            <span>RESULT</span>
            <strong>{model.result.outcome}</strong>
          </div>
          <div className="evidence-result">
            <span>ADDITIONAL EVIDENCE</span>
            <strong>{model.result.additional_evidence.status.replace("_", " ")}</strong>
          </div>
          {model.result.additional_evidence.hinge && (
            <div className="hinge-result">
              <span>HINGE</span>
              <strong>{model.result.additional_evidence.hinge.label}</strong>
              <small>{model.result.additional_evidence.hinge.permitted_source_classes.join(" · ")}</small>
            </div>
          )}
          <div className="quantity-result">
            <span>EXACT QUANTITY</span>
            <strong>UNRESOLVED</strong>
            <small>{invariant ? "IRRELEVANT TO THIS ACTION" : "ACTION-SENSITIVE"}</small>
          </div>
          <p className="stop-rule">
            {invariant
              ? "MUSTER stops here because resolving 97 vs 100 cannot change the action."
              : "The same uncertainty now changes the action, so MUSTER asks for proof."}
          </p>
        </section>
      </main>

      <footer className="procurement-footer">
        <span>{model.provenance.description}</span>
        <strong>Same machinery · different domain and policy</strong>
      </footer>
    </div>
  );
}
