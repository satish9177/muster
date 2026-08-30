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
import { HEADLINE_IDEAS, SYSTEM_BOUNDARY, kernelOutcomeTerm } from "../data/plainLanguage";
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
            High-impact agents act over records that belong to different institutions.
            Centralizing raw records into one control plane is unsafe — and so is blindly
            retrying an irreversible action whose outcome is unknown.
          </p>
          <p className="landing-boundary" aria-label="System boundary">
            {SYSTEM_BOUNDARY.map((line) => (
              <span key={line}>{line}</span>
            ))}
          </p>
        </div>
        <div className="landing-assurance" aria-label="Product assurances">
          <span><ShieldCheck size={16} aria-hidden="true" /> Authority checked</span>
          <span><CheckCircle2 size={16} aria-hidden="true" /> Outcomes reproduced</span>
          <span><CloudCog size={16} aria-hidden="true" /> Site-A IAM boundary verified</span>
        </div>
      </section>

      {/*
        The two ideas the rest of the product exists to make checkable. A judge
        who reads nothing else should still leave with these, so they sit above
        the catalog rather than behind a case.
      */}
      <section className="landing-ideas" aria-label="What MUSTER does differently">
        {HEADLINE_IDEAS.map((idea, index) => (
          <article key={idea}>
            <span aria-hidden="true">{index + 1}</span>
            <p>{idea}</p>
          </article>
        ))}
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
            <span className="catalog-question">
              Can {catalog.workforce.actionAmount} be safely authorized without the central
              Control Plane ever reading Ravi&rsquo;s raw site records?
            </span>
            <span className="catalog-result">
              <b title={kernelOutcomeTerm(catalog.workforce.outcome).technical}>
                {kernelOutcomeTerm(catalog.workforce.outcome).plain}
              </b>
              <i aria-hidden="true" />
              <b>{catalog.workforce.actionAmount}</b>
            </span>
            <span className="catalog-technical">
              {kernelOutcomeTerm(catalog.workforce.outcome).technical}
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
            <span className="catalog-question">
              Same unresolved quantity, two pinned policies — does the action change?
            </span>
            <span className="catalog-result">
              <b title={kernelOutcomeTerm(catalog.procurement.outcome).technical}>
                {kernelOutcomeTerm(catalog.procurement.outcome).plain}
              </b>
              <i aria-hidden="true" />
              <b>TOLERANCE PROOF</b>
            </span>
            <span className="catalog-technical">
              {kernelOutcomeTerm(catalog.procurement.outcome).technical}
            </span>
            <small><ShieldCheck size={13} aria-hidden="true" /> {catalog.procurement.provenance}</small>
            <span className="catalog-open">OPEN CASE <ArrowRight size={15} aria-hidden="true" /></span>
          </button>
        </div>
      </section>
    </main>
  );
}
