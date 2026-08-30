import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  CircleDotDashed,
  FileCheck2,
  LockKeyhole,
  RefreshCcw,
  Scale,
  Warehouse,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  ADMISSIBLE_ENVELOPE,
  HINGE,
  INERT_CLAIM,
  REACHABLE_ACTIONS,
  kernelOutcomeTerm,
} from "../data/plainLanguage";
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
  const outcome = kernelOutcomeTerm(model.result.outcome);
  return (
    <div className="procurement-shell">
      <section className="procurement-heading">
        <div>
          <span className="case-kicker">PROCUREMENT / SUPPLIER DELIVERY</span>
          <h1>{model.case.po_id} <span>·</span> {model.case.title}</h1>
          <p>One unresolved fact. Two pinned policies. The action decides whether proof is needed.</p>
        </div>
        <div className="kernel-note">
          <Scale size={18} aria-hidden="true" />
          <span><strong>Deterministic cross-domain proof</strong>Same MUSTER kernel · no Gemini/cloud claim</span>
        </div>
        {/*
          Said here as well as in the footer, because the product bar no longer
          says it for every screen: this one is a local kernel proof and was
          never a Google Cloud replay.
        */}
        <span className="view-provenance">{model.provenance.label}</span>
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
                    ? INERT_CLAIM.plain
                    : "LOWER BOUND · NOT FINAL QUANTITY"}
                </small>
              </article>
            ))}
          </div>
          <div className="disagreement-callout">
            <AlertTriangle size={17} aria-hidden="true" />
            <div>
              <strong>KNOWN QUANTITY RANGE · {model.uncertainty.lower_bound.quantity}–{model.uncertainty.upper_bound.quantity} UNITS</strong>
              <span>Warehouse-authorized lower bound; exact delivered quantity remains unresolved</span>
            </div>
          </div>
          <dl className="source-facts">
            <div><dt>Tenant</dt><dd>{model.case.tenant_id}</dd></div>
            <div><dt>Authority scope</dt><dd>PURCHASE_ORDER / {model.case.po_id}</dd></div>
            <div>
              <dt className="stacked-term" title={ADMISSIBLE_ENVELOPE.technical}>
                {ADMISSIBLE_ENVELOPE.plain}
              </dt>
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
            >{policy === "FIXED_TOLERANCE" ? model.policy.display_name : "Fixed contract"}</button>
            <button
              type="button"
              className={policy === "PER_UNIT" ? "active" : ""}
              onClick={() => setPolicy("PER_UNIT")}
            >{policy === "PER_UNIT" ? model.policy.display_name : "Per-unit contract"}</button>
          </div>
          <div className="policy-definition">
            <LockKeyhole size={16} aria-hidden="true" />
            <div>
              <span>POLICY</span>
              <strong>{model.policy.display_rule}</strong>
              <code>{model.policy.policy_id} · {model.policy.version}</code>
            </div>
          </div>
          {invariant ? (
            <div className="invariant-alternative">
              <span>{model.uncertainty.admissible_min}–{model.uncertainty.admissible_max} units</span>
              <ArrowRight size={16} aria-hidden="true" />
              <strong>{model.result.proposedAmount}</strong>
            </div>
          ) : (
            <div className="alternative-list">
              {model.alternatives.map((alternative) => (
                <div key={alternative.quantity}>
                  <span>{alternative.quantity} units</span>
                  <ArrowRight size={15} aria-hidden="true" />
                  <strong>{alternative.amount}</strong>
                </div>
              ))}
            </div>
          )}
          <p className="contract-note">
            {model.policy.display_note}
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
            <strong title={outcome.technical}>{outcome.plain}</strong>
            <small className="term-technical">{outcome.technical}</small>
            <em className="term-explanation">{outcome.explanation}</em>
          </div>
          <div className="reachable-result">
            <span title={REACHABLE_ACTIONS.technical}>{REACHABLE_ACTIONS.plain}</span>
            <strong>{model.result.reachable_action_count}</strong>
            <small className="term-technical">{REACHABLE_ACTIONS.technical}</small>
          </div>
          <div className="evidence-result">
            <span>NEXT EVIDENCE REQUEST</span>
            <strong>{model.result.additional_evidence.display_status}</strong>
          </div>
          {model.result.additional_evidence.hinge && (
            <div className="hinge-result">
              <span title={HINGE.technical}>{HINGE.plain}</span>
              <strong>{model.result.additional_evidence.hinge.label}</strong>
              <small>NEXT AUTHORIZED SOURCE · {model.result.additional_evidence.hinge.permitted_source_classes.join(" · ")}</small>
            </div>
          )}
          <div className="quantity-result">
            <span>EXACT DELIVERED QUANTITY</span>
            <strong>{model.result.exact_quantity_relevance}</strong>
            <small>Current value remains {model.uncertainty.status}</small>
          </div>
          <p className="stop-rule">{model.result.explanation}</p>
        </section>
      </main>

      <footer className="procurement-footer">
        <span>{model.provenance.label}</span>
        <strong>SAME UNCERTAINTY · SAME KERNEL · DIFFERENT POLICY · DIFFERENT EVIDENCE REQUIREMENT</strong>
      </footer>
    </div>
  );
}
