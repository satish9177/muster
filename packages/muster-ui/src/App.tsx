import { AlertTriangle, RefreshCcw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { CaseHeader } from "./components/CaseHeader";
import { CaseTrace } from "./components/CaseTrace";
import { Inspector } from "./components/Inspector";
import { heroCaseClient } from "./data/caseClient";
import type { HeroCaseViewModel } from "./data/readModel";

export function App() {
  const [model, setModel] = useState<HeroCaseViewModel | null>(null);
  const [activeId, setActiveId] = useState("boundary");
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);

    heroCaseClient
      .load(controller.signal)
      .then(setModel)
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Case read model unavailable");
      });

    return () => controller.abort();
  }, [reloadKey]);

  const activeEvent = useMemo(
    () => model?.events.find((event) => event.id === activeId) ?? model?.events[0],
    [activeId, model],
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

  if (!model || !activeEvent) {
    return (
      <main className="load-state" aria-label="Loading Ravi case">
        <span className="loading-mark" aria-hidden="true">M</span>
        <p>Opening authorized case record…</p>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <CaseHeader model={model} />
      <main className="case-workspace">
        <CaseTrace events={model.events} activeId={activeEvent.id} onSelect={setActiveId} />
        <Inspector event={activeEvent} model={model} />
      </main>
      <footer className="app-footer">
        <span>{model.provenance.description}</span>
        <span>{model.provenance.basis}</span>
      </footer>
    </div>
  );
}
