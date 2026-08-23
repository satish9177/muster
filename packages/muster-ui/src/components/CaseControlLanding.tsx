import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CloudCog,
  HardHat,
  RefreshCcw,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useState } from "react";

import { buildCaseCatalog, type CaseCatalogViewModel } from "../data/caseCatalog";
import { heroCaseClient } from "../data/caseClient";
import { procurementCaseClient } from "../data/procurementClient";
import type { CaseKind } from "./CaseSelector";

interface CaseControlLandingProps {
  onOpen: (kind: Exclude<CaseKind, "cases">) => void;
}

export function CaseControlLanding({ onOpen }: CaseControlLandingProps) {
  const [catalog, setCatalog] = useState<CaseCatalogViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    Promise.all([
      heroCaseClient.load(controller.signal),
      procurementCaseClient.load("FIXED_TOLERANCE", controller.signal),
    ])
      .then(([workforce, procurement]) => setCatalog(buildCaseCatalog(workforce, procurement)))
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Case catalog unavailable");
      });
    return () => controller.abort();
  }, [reloadKey]);

  if (error) {
    return (
      <main className="landing-state error-state">
        <AlertTriangle size={28} aria-hidden="true" />
        <h1>Case catalog unavailable</h1>
        <p>{error}</p>
        <button type="button" onClick={() => setReloadKey((key) => key + 1)}>
          <RefreshCcw size={15} aria-hidden="true" /> Retry
        </button>
      </main>
    );
  }

  if (!catalog) {
    return (
      <main className="landing-state" aria-label="Loading enterprise cases">
        <span className="loading-mark" aria-hidden="true">M</span>
        <p>Opening enterprise case catalog…</p>
      </main>
    );
  }

  return (
    <main className="case-control-landing">
      <section className="landing-hero">
        <div>
          <span className="landing-kicker">ENTERPRISE CASE CONTROL</span>
          <h1>Consequential decisions,<br />proved before action.</h1>
          <p>
            One control surface for source authority, pinned policy, deterministic proof,
            and exactly authorized execution.
          </p>
        </div>
        <div className="landing-assurance" aria-label="Product assurances">
          <span><ShieldCheck size={16} aria-hidden="true" /> Authority checked</span>
          <span><CheckCircle2 size={16} aria-hidden="true" /> Outcomes reproduced</span>
          <span><CloudCog size={16} aria-hidden="true" /> Site-A IAM boundary verified</span>
        </div>
      </section>

      <section className="case-catalog" aria-labelledby="case-catalog-title">
        <div className="catalog-heading">
          <span className="section-label">CASES</span>
          <h2 id="case-catalog-title">Active proof records</h2>
          <p>Choose a case to inspect its evidence, decision, and action boundary.</p>
        </div>
        <div className="catalog-cards">
          <button type="button" className="catalog-card workforce-card" onClick={() => onOpen("workforce")}>
            <span className="catalog-icon"><HardHat size={20} aria-hidden="true" /></span>
            <span className="catalog-domain">{catalog.workforce.domain}</span>
            <strong>{catalog.workforce.title}</strong>
            <span className="catalog-result">
              <b>{catalog.workforce.outcome}</b>
              <i aria-hidden="true" />
              <b>{catalog.workforce.actionAmount}</b>
            </span>
            <small className={catalog.workforce.verifiedCloud ? "verified" : ""}>
              <CloudCog size={13} aria-hidden="true" /> {catalog.workforce.provenance}
            </small>
            <span className="catalog-open">OPEN CASE <ArrowRight size={15} aria-hidden="true" /></span>
          </button>

          <button type="button" className="catalog-card procurement-card" onClick={() => onOpen("procurement")}>
            <span className="catalog-icon"><Boxes size={20} aria-hidden="true" /></span>
            <span className="catalog-domain">{catalog.procurement.domain}</span>
            <strong>{catalog.procurement.title}</strong>
            <span className="catalog-result">
              <b>{catalog.procurement.outcome}</b>
              <i aria-hidden="true" />
              <b>TOLERANCE PROOF</b>
            </span>
            <small><ShieldCheck size={13} aria-hidden="true" /> {catalog.procurement.provenance}</small>
            <span className="catalog-open">OPEN CASE <ArrowRight size={15} aria-hidden="true" /></span>
          </button>
        </div>
      </section>
    </main>
  );
}
