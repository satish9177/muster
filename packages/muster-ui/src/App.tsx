import { AlertTriangle, RefreshCcw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ActionGatePanel } from "./components/ActionGatePanel";
import { CaseControlLanding } from "./components/CaseControlLanding";
import { CaseSelector, type CaseKind } from "./components/CaseSelector";
import { CaseHeader } from "./components/CaseHeader";
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
  const [view, setView] = useState<"overview" | "evidence" | "planner" | "durability">("overview");

  useEffect(() => {
    const controller = new AbortController();
    setError(null);

    heroCaseClient
      .load(controller.signal)
      .then(async (loaded) => {
        setModel(loaded);
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
    <div className="app-shell">
      {view !== "durability" && (
        <CaseHeader
          model={model}
          gate={gate}
          executing={executing}
          onExecute={() => void executeProposal()}
        />
      )}
      <nav className="case-view-nav" aria-label="Ravi case views">
        <button type="button" className={view === "overview" && activeEvent.id !== "action" ? "active" : ""} onClick={() => setView("overview")}>Overview</button>
        <button type="button" className={view === "evidence" ? "active" : ""} onClick={() => setView("evidence")}>Evidence</button>
        <button type="button" className={view === "planner" ? "active" : ""} onClick={() => setView("planner")}>Decision</button>
        <button type="button" className={view === "durability" ? "active" : ""} onClick={() => setView("durability")}>Durable case</button>
        <button type="button" className={view === "overview" && activeEvent.id === "action" ? "active" : ""} onClick={() => { setView("overview"); setActiveId("action"); }}>Action</button>
      </nav>
      {view === "evidence" ? (
        <RaviEvidence />
      ) : view === "planner" ? (
        <EvidencePlanner />
      ) : view === "durability" ? (
        <DurableCaseHistory />
      ) : (
        <div className="workforce-overview">
          <ActionGatePanel gate={gate} unavailableReason={gateError} />
          <main className="case-workspace">
            <CaseTrace events={displayedModel.events} activeId={activeEvent.id} onSelect={setActiveId} />
            <Inspector event={activeEvent} model={displayedModel} />
          </main>
        </div>
      )}
      {view !== "durability" && (
        <footer className="app-footer">
          <span>{model.provenance.description}</span>
          <span>{model.provenance.basis}</span>
        </footer>
      )}
    </div>
  );
}
