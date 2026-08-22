import { Binary, ShieldCheck, Sparkles } from "lucide-react";

import type { TraceEvent } from "../data/readModel";
import { TraceIcon } from "./TraceIcon";

interface CaseTraceProps {
  events: TraceEvent[];
  activeId: string;
  onSelect: (id: string) => void;
}

export function CaseTrace({ events, activeId, onSelect }: CaseTraceProps) {
  return (
    <section className="trace-panel" aria-labelledby="trace-title">
      <div className="panel-heading trace-heading">
        <div>
          <span className="section-label">AUTHORIZED CASE PATH</span>
          <h2 id="trace-title">Decision trace</h2>
        </div>
        <div className="operation-legend" aria-label="Operation types">
          <span title="Model interpretation occurs inside a source agent">
            <Sparkles size={13} aria-hidden="true" /> AI interpretation
          </span>
          <span title="The source signs a narrow authorized attestation">
            <ShieldCheck size={13} aria-hidden="true" /> source authority
          </span>
          <span title="Deterministic code plans, validates, rebuilds, and decides">
            <Binary size={13} aria-hidden="true" /> deterministic
          </span>
        </div>
      </div>

      <ol className="trace-list">
        {events.map((event, index) => {
          const active = event.id === activeId;
          const siteAgent = event.id === "site-agent";
          return (
            <li
              className={`trace-entry ${event.kind} ${active ? "active" : ""}`}
              key={event.id}
              style={{ "--entry-index": index } as React.CSSProperties}
            >
              <span className="trace-spine" aria-hidden="true" />
              <button
                type="button"
                className="trace-button"
                onClick={() => onSelect(event.id)}
                aria-current={active ? "step" : undefined}
                aria-label={`Inspect ${event.title}`}
              >
                <span className="trace-sequence">{event.sequence}</span>
                <span className="trace-icon">
                  <TraceIcon kind={event.kind} siteAgent={siteAgent} />
                </span>
                <span className="trace-content">
                  <span className="trace-meta">
                    <span className="trace-eyebrow">{event.eyebrow}</span>
                    <span className="trace-actor">{event.actor}</span>
                  </span>
                  <span className="trace-title-row">
                    <strong>{event.title}</strong>
                    <span className={`event-result ${event.resultTone}`}>{event.result}</span>
                  </span>
                  <span className="trace-summary">{event.summary}</span>
                  {event.tags.length > 0 && (
                    <span className="trace-tags" aria-label="Event attributes">
                      {event.tags.map((tag) => (
                        <span key={tag}>{tag}</span>
                      ))}
                    </span>
                  )}
                </span>
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
