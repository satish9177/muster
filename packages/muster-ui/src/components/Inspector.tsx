import {
  Binary,
  CircleEllipsis,
  KeyRound,
  LockKeyhole,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import type { HeroCaseViewModel, TraceEvent } from "../data/readModel";
import { TraceIcon } from "./TraceIcon";

interface InspectorProps {
  event: TraceEvent;
  model: HeroCaseViewModel;
}

export function Inspector({ event, model }: InspectorProps) {
  const detail = event.inspector;

  return (
    <aside className="inspector-panel" aria-labelledby="inspector-title">
      <div className={`inspector-accent ${event.resultTone}`} aria-hidden="true" />
      <div className="panel-heading inspector-heading">
        <div>
          <span className="section-label">PROVENANCE INSPECTOR</span>
          <h2 id="inspector-title">Selected event</h2>
        </div>
        <span className={`inspector-icon ${event.kind}`}>
          <TraceIcon kind={event.kind} siteAgent={event.id === "site-agent"} />
        </span>
      </div>

      <div className="inspector-event">
        <span>{event.sequence} / {event.eyebrow}</span>
        <h3>{event.title}</h3>
        <span className={`inspector-result ${event.resultTone}`}>{event.result}</span>
      </div>

      {event.kind === "rebuild" && (
        <div className="rebuild-proof">
          <Binary size={15} aria-hidden="true" />
          <strong>{detail.deterministicDecision}</strong>
        </div>
      )}

      {event.kind === "boundary" && (
        <div className="boundary-callout">
          <LockKeyhole size={18} aria-hidden="true" />
          <div>
            <strong>Security boundary held</strong>
            <span>The Control Plane identity was denied Site-A raw evidence access by GCP IAM.</span>
          </div>
          <b>{event.httpStatus}</b>
        </div>
      )}

      <dl className="provenance-grid">
        <ProvenanceRow term="Source class" value={detail.sourceClass} />
        <ProvenanceRow term="Source identity" value={detail.sourceIdentity} />
        <ProvenanceRow
          term="Signing key"
          value={detail.keyId ?? "Not applicable"}
          icon={<KeyRound size={13} aria-hidden="true" />}
        />
        <ProvenanceRow term="Authority grant" value={detail.authorityGrant} />
      </dl>

      <section className="predicate-section" aria-labelledby="predicate-title">
        <span className="mini-heading" id="predicate-title">PREDICATE / NARROW DISCLOSURE</span>
        <div className="predicate-list">
          {detail.predicates.map((predicate) => (
            <code key={predicate}>{predicate}</code>
          ))}
        </div>
        <p>{detail.disclosure}</p>
      </section>

      <div className="operation-checks">
        <OperationCheck
          icon={<ShieldCheck size={15} aria-hidden="true" />}
          label="Q-12 authority"
          value={detail.q12Result}
          tone={detail.q12Result.includes("PASSED") ? "pass" : "plain"}
        />
        <OperationCheck
          icon={<Sparkles size={15} aria-hidden="true" />}
          label="Model interpretation"
          value={detail.modelInterpretation}
          tone={detail.modelInterpretation.includes("Gemini") ? "ai" : "plain"}
        />
        <OperationCheck
          icon={<Binary size={15} aria-hidden="true" />}
          label="Deterministic code"
          value={detail.deterministicDecision}
          tone={detail.deterministicDecision.startsWith("Yes") ? "code" : "plain"}
        />
      </div>

      <div className="inspector-footer">
        <div className="unresolved-note">
          <CircleEllipsis size={15} aria-hidden="true" />
          <span>
            <strong>Still unresolved</strong>
            {model.unresolved.join(" · ")}
          </span>
        </div>
        <p>{detail.provenanceNote}</p>
      </div>
    </aside>
  );
}

interface ProvenanceRowProps {
  term: string;
  value: string;
  icon?: React.ReactNode;
}

function ProvenanceRow({ term, value, icon }: ProvenanceRowProps) {
  return (
    <div>
      <dt>{term}</dt>
      <dd>{icon}{value}</dd>
    </div>
  );
}

interface OperationCheckProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: "pass" | "ai" | "code" | "plain";
}

function OperationCheck({ icon, label, value, tone }: OperationCheckProps) {
  return (
    <div className={`operation-check ${tone}`}>
      <span className="operation-check-icon">{icon}</span>
      <span>
        <small>{label}</small>
        <strong>{value}</strong>
      </span>
    </div>
  );
}
