import { AlertTriangle, RefreshCcw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ActionGatePanel } from "./components/ActionGatePanel";
import { CaseControlLanding } from "./components/CaseControlLanding";
import { CloudGateProof, CloudGateProofFooter } from "./components/CloudGateProof";
import { CaseSelector, type CaseKind } from "./components/CaseSelector";
import { CaseHeader } from "./components/CaseHeader";
import { CaseNarrative } from "./components/CaseNarrative";
import { CaseTrace } from "./components/CaseTrace";
import { DurableCaseHistory } from "./components/DurableCaseHistory";
import { EvidencePlanner } from "./components/EvidencePlanner";
import { Inspector } from "./components/Inspector";
import { ProcurementCase } from "./components/ProcurementCase";
import { RaviEvidence } from "./components/RaviEvidence";
import {
  actionGateClient,
  withActionGate,
  type ActionGateReadModel,
} from "./data/actionGate";
import { heroCaseClient } from "./data/caseClient";
import type { HeroCaseViewModel } from "./data/readModel";
import { runtimeMode } from "./data/runtimeMode";

type CaseView = "overview" | "evidence" | "planner" | "durability" | "action";

/** Tab order, and the chronology a first-time reader is walked through. */
const CASE_VIEWS: ReadonlyArray<readonly [CaseView, string]> = [
  ["overview", "Overview"],
  ["evidence", "Evidence"],
  ["planner", "Decision"],
  ["durability", "Durable case"],
  ["action", "Action"],
];

/**
 * What each screen actually is.
 *
 * The product bar says which *build* this is and nothing more. Provenance is
 * per screen because it differs per screen: three of these replay a finished
 * Google Cloud execution, one projects that same verified artifact through the
 * deterministic planner without any new run, and one is a local proof that
 * never touched GCP. One global "verified replay" banner over all of them
 * would be a claim about the local screen that is not true -- and the Decision
 * screen needs both halves said at once, because its *source* is the verified
 * GCP artifact while its *computation* is local and deterministic. Naming only
 * the second would read as though the screen had no cloud provenance; naming
 * only the first would suggest the tab reran GCP or Gemini. It did neither.
 */
const SCREEN_PROVENANCE: Record<CaseView, string> = {
  overview: "VERIFIED GCP REPLAY — NOT LIVE TELEMETRY",
  evidence: "VERIFIED GCP REPLAY — NOT LIVE TELEMETRY",
  planner: "DETERMINISTIC PROJECTION OF VERIFIED GCP ARTIFACT — NO NEW CLOUD OR MODEL RUN",
  durability: "LOCAL POSTGRESQL DURABILITY PROOF",
  action: "VERIFIED GCP REPLAY — NOT LIVE TELEMETRY",
};

/**
 * The views whose content is taller than one viewport.
 *
 * These let the page itself scroll rather than clipping inside a fixed shell;
 * everything else still fits one screen and keeps its fitted layout.
 */
const SCROLLING_VIEWS = new Set<CaseView>(["overview", "action"]);

export function App() {
  const [caseKind, setCaseKind] = useState<CaseKind>("cases");

  return (
    <div className="product-shell">
      <CaseSelector active={caseKind} onSelect={setCaseKind} />
      {caseKind === "cases" ? (
        <CaseControlLanding onOpen={setCaseKind} />
      ) : caseKind === "workforce" ? (
        <WorkforceCase />
      ) : (
        <ProcurementCase />
      )}
    </div>
  );
}

function WorkforceCase() {
  const [model, setModel] = useState<HeroCaseViewModel | null>(null);
  const [activeId, setActiveId] = useState("boundary");
  const [error, setError] = useState<string | null>(null);
  const [gate, setGate] = useState<ActionGateReadModel | null>(null);
  const [gateError, setGateError] = useState<string | null>(null);
  const [executing, setExecuting] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [view, setView] = useState<CaseView>("overview");

  useEffect(() => {
    const controller = new AbortController();
    setError(null);

    heroCaseClient
      .load(controller.signal)
      .then(async (loaded) => {
        setModel(loaded);
        //  The replay-only build has no `/api/demo` to reach and must not try:
        //  a failed request here would surface as a Gate error about a backend
        //  that this bundle was deliberately built without.
        if (runtimeMode.replayOnly) return;
        try {
          setGate(await actionGateClient.loadProposal(loaded.id, controller.signal));
          setGateError(null);
        } catch (reason: unknown) {
          if (reason instanceof DOMException && reason.name === "AbortError") return;
          setGate(null);
          setGateError(
            reason instanceof Error
              ? reason.message
              : "Local sandbox Action Gate is unavailable; cloud replay remains NOT_EXECUTED",
          );
        }
      })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Case read model unavailable");
      });

    return () => controller.abort();
  }, [reloadKey]);

  async function executeProposal(): Promise<void> {
    //  Fail closed at the call site as well as at the control. A judge build
    //  has no mutation endpoint, and this function must not be reachable in it
    //  even through a stale handler or a future refactor of the header.
    if (runtimeMode.replayOnly) return;
    if (!model || !gate || executing) return;
    setExecuting(true);
    setGateError(null);
    try {
      setGate(await actionGateClient.execute(model.id, gate.proposalId));
    } catch (reason: unknown) {
      setGateError(reason instanceof Error ? reason.message : "Sandbox execution was refused");
    } finally {
      setExecuting(false);
    }
  }

  const activeEvent = useMemo(
    () => {
      if (!model) return undefined;
      const displayed = withActionGate(model, gate);
      return displayed.events.find((event) => event.id === activeId) ?? displayed.events[0];
    },
    [activeId, gate, model],
  );

  const displayedModel = useMemo(
    () => (model ? withActionGate(model, gate) : null),
    [gate, model],
  );

  if (error) {
    return (
      <main className="load-state error-state">
        <AlertTriangle size={28} aria-hidden="true" />
        <h1>Case view unavailable</h1>
        <p>{error}</p>
        <button type="button" onClick={() => setReloadKey((key) => key + 1)}>
          <RefreshCcw size={15} aria-hidden="true" /> Retry
        </button>
      </main>
    );
  }

  if (!model || !displayedModel || !activeEvent) {
    return (
      <main className="load-state" aria-label="Loading Ravi case">
        <span className="loading-mark" aria-hidden="true">M</span>
        <p>Opening authorized case record…</p>
      </main>
    );
  }

  return (
    <div className={`app-shell ${SCROLLING_VIEWS.has(view) ? "shell-scrolls" : ""}`}>
      {view !== "durability" && (
        <CaseHeader
          model={model}
          gate={gate}
          executing={executing}
          onExecute={() => void executeProposal()}
        />
      )}
      <nav className="case-view-nav" aria-label="Ravi case views">
        {CASE_VIEWS.map(([id, label]) => (
          <button
            key={id}
            type="button"
            className={view === id ? "active" : ""}
            onClick={() => setView(id)}
          >
            {label}
          </button>
        ))}
        <span className="view-provenance" aria-label="What this screen is">
          {SCREEN_PROVENANCE[view]}
        </span>
      </nav>
      {view === "evidence" ? (
        <RaviEvidence />
      ) : view === "planner" ? (
        <EvidencePlanner />
      ) : view === "durability" ? (
        <DurableCaseHistory />
      ) : view === "action" ? (
        /*
          The Action view is the end of the case, and the only place the
          finished Google Cloud execution proof appears. It is a separate view
          rather than a band on the Overview because a reader shown the receipt
          first has been told the ending before the case: what was claimed, what
          was refused and what was signed all stop mattering once the outcome is
          already on the screen.

          In the replay-only judge build the final cloud proof is the *whole*
          body. The local PostgreSQL Gate is a developer surface, and a notice
          about it under the receipt puts a second, local execution surface on
          the one screen whose subject is the verified cloud execution -- which
          is exactly the mixture a reader must not have to untangle. The
          developer build still renders it, below the proof, where a local Gate
          actually exists to talk about.
        */
        <div className="workforce-action">
          <CloudGateProof />
          {!runtimeMode.replayOnly && (
            <ActionGatePanel gate={gate} unavailableReason={gateError} />
          )}
        </div>
      ) : (
        <div className="workforce-overview">
          <CaseNarrative model={displayedModel} />
          <main className="case-workspace">
            <CaseTrace events={displayedModel.events} activeId={activeEvent.id} onSelect={setActiveId} />
            <Inspector event={activeEvent} model={displayedModel} />
          </main>
        </div>
      )}
      {/*
        Provenance belongs to the screen above it. The hero case's footer names
        the analysis-only cloud replay that the Overview and Evidence views are
        built from; the Action view is a separate five-execution proof and
        carries its own.
      */}
      {view === "action" ? (
        <CloudGateProofFooter />
      ) : view !== "durability" ? (
        <footer className="app-footer">
          <span>{model.provenance.description}</span>
          <span>{model.provenance.basis}</span>
        </footer>
      ) : null}
    </div>
  );
}
