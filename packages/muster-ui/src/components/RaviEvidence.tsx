import {
  AlertTriangle,
  ArrowDown,
  Binary,
  CheckCircle2,
  Cloud,
  FileText,
  Image,
  KeyRound,
  LockKeyhole,
  RefreshCcw,
  ShieldCheck,
  Sparkles,
  UserRound,
} from "lucide-react";
import { useEffect, useState } from "react";

import { evidenceClient } from "../data/evidenceClient";
import type {
  EvidenceAgentViewModel,
  RaviEvidenceViewModel,
} from "../data/evidenceReadModel";

export function RaviEvidence() {
  const [model, setModel] = useState<RaviEvidenceViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    evidenceClient
      .load(controller.signal)
      .then(setModel)
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Ravi Evidence unavailable");
      });
    return () => controller.abort();
  }, [reloadKey]);

  if (error) {
    return (
      <main className="evidence-state error-state">
        <AlertTriangle size={25} aria-hidden="true" />
        <h2>Evidence proof unavailable</h2>
        <p>{error}</p>
        <button type="button" onClick={() => setReloadKey((key) => key + 1)}>
          <RefreshCcw size={14} aria-hidden="true" /> Retry
        </button>
      </main>
    );
  }

  if (!model) {
    return <main className="evidence-state"><span className="loading-mark">M</span><p>Loading verified evidence path…</p></main>;
  }

  return (
    <main className="evidence-view">
      <section className="evidence-provenance" aria-label="Verified cloud execution metadata">
        <div className="evidence-provenance-title">
          <Cloud size={18} aria-hidden="true" />
          <span>
            <small>VERIFIED CLOUD EXECUTION REPLAY · ravi-cloud-execution.json</small>
            <strong>{model.execution.name}</strong>
            <small>OBSERVED MODEL · IAM · FACTS · Q-12 · RESULT</small>
          </span>
        </div>
        <dl>
          <div><dt>Cloud Run</dt><dd>{model.execution.cloudRunRegion}</dd></div>
          <div><dt>Gemini model</dt><dd>{model.execution.modelName}</dd></div>
          <div><dt>Vertex location</dt><dd>{model.execution.modelLocation}</dd></div>
          <div><dt>Executed</dt><dd>{formatTimestamp(model.execution.timestamp)}</dd></div>
        </dl>
      </section>

      <section className="evidence-agents" aria-label="Gemini evidence paths">
        <EvidenceAgentCard agent={model.worker} kind="worker" modelName={model.execution.modelName} />
        <EvidenceAgentCard agent={model.employer} kind="employer" modelName={model.execution.modelName} />
        <EvidenceAgentCard
          agent={model.site}
          kind="site"
          modelName={model.execution.modelName}
          boundary={model.boundary}
        />
      </section>

      <section className="responsibility-split" aria-label="Gemini and MUSTER responsibilities">
        <div className="gemini-role">
          <span className="role-icon"><Sparkles size={17} aria-hidden="true" /></span>
          <div>
            <small>{model.execution.modelName} / INTERPRETATION</small>
            <strong>Gemini interprets source-local evidence and produces candidate facts.</strong>
          </div>
          <span className="role-stop">STOPS HERE</span>
        </div>
        <div className="role-divider" aria-hidden="true"><ArrowDown size={15} /></div>
        <div className="muster-role">
          <span className="role-icon"><Binary size={17} aria-hidden="true" /></span>
          <div>
            <small>DETERMINISTIC MUSTER / CONSEQUENCE</small>
            <strong>Deterministic code validates authority, applies pinned policy, determines consequential outcomes, and controls execution.</strong>
          </div>
          <span className="role-outcome"><b>{model.deterministic.outcome}</b>{model.deterministic.action} · {model.deterministic.execution}</span>
        </div>
      </section>

      <footer className="evidence-audit-note">
        IMPLEMENTATION AUDIT · ravi-evidence-proof.json · committed request shape/modality, not runtime telemetry · {model.provenance.commit.slice(0, 12)}
      </footer>
    </main>
  );
}

interface EvidenceAgentCardProps {
  agent: EvidenceAgentViewModel;
  kind: "worker" | "employer" | "site";
  modelName: string;
  boundary?: RaviEvidenceViewModel["boundary"];
}

function EvidenceAgentCard({ agent, kind, modelName, boundary }: EvidenceAgentCardProps) {
  return (
    <article className={`evidence-agent-card ${kind}`}>
      <header>
        <span className="agent-avatar">
          {kind === "worker" ? <UserRound size={17} /> : kind === "site" ? <ShieldCheck size={17} /> : <FileText size={17} />}
        </span>
        <span><small>{agent.captureStatus}</small><strong>{agent.label}</strong></span>
        <em>{agent.modalities.join(" + ")}</em>
      </header>

      <div className="capture-note">
        {kind === "worker"
          ? "TEXT INPUT · COMMITTED ADK PATH · WORKER NOT RERUN IN VERIFIED STAGE-90 CLOUD HERO"
          : kind === "employer"
            ? "STAGE-90 CLOUD RESULT VERIFIED · TEXT/PLAIN REQUEST SHAPE AUDITED"
            : "STAGE-90 CLOUD RESULT VERIFIED · RAW PNG + TEXT ADK REQUEST SHAPE AUDITED"}
      </div>

      {boundary && (
        <div className="iam-proof">
          <span><LockKeyhole size={15} aria-hidden="true" />The Control Plane identity was denied access to Site-A raw evidence by GCP IAM.</span>
          <strong>{boundary.result} · HTTP {boundary.httpStatus} · {boundary.enforcement}</strong>
          <span><CheckCircle2 size={15} aria-hidden="true" />The Site Agent identity was allowed.</span>
        </div>
      )}

      <section className="material-block">
        <span className="evidence-mini-label">SOURCE MATERIAL · IMPLEMENTATION AUDIT</span>
        {agent.statement && <blockquote>“{agent.statement}”</blockquote>}
        <div className="material-list">
          {agent.sourceMaterial.map((material) => (
            <div key={material.ref}>
              {material.mediaType === "image/png" ? <Image size={14} aria-hidden="true" /> : <FileText size={14} aria-hidden="true" />}
              <span><strong>{material.file}</strong><small>{material.mediaType} · {material.delivery}</small></span>
            </div>
          ))}
        </div>
      </section>

      <div className="agent-pipeline" aria-label={`${agent.label} interpretation pipeline`}>
        <span>{agent.runtime}</span><i>↓</i>
        <span className="gemini-step">
          <Sparkles size={12} /> {kind === "worker" ? "GEMINI PATH COMMITTED" : `${modelName} OBSERVED`}
        </span><i>↓</i>
        <span>{kind === "worker" ? "UNSIGNED CLAIM" : "STRUCTURED CANDIDATE"}</span>
      </div>

      <section className="candidate-block">
        <span className="evidence-mini-label">
          {kind === "worker"
            ? "CLAIM INPUT · VERIFIED REPLAY · NOT MODEL TELEMETRY"
            : "MODEL-DERIVED CANDIDATE · VERIFIED CLOUD ARTIFACT"}
        </span>
        {agent.candidateFacts.map((fact) => <code key={fact}>{fact}</code>)}
        {kind === "worker" ? (
          <b className="claim-only">CLAIM ONLY — INERT</b>
        ) : (
          <div className="trust-rail" aria-label="Post-model deterministic controls">
            <span>VALIDATED</span><i>→</i>
            <span>SIGNED · {agent.signerKeys.join(", ")}</span><i>→</i>
            <span>{agent.q12Passed ? "Q-12 PASSED" : "Q-12 REFUSED"}</span>
          </div>
        )}
      </section>

      <details>
        <summary>Validation, signature &amp; Q-12</summary>
        <div className="evidence-details">
          <strong>Accepted model output</strong><p>{agent.acceptedCandidate}</p>
          <strong>Deterministic validation</strong><ul>{agent.validation.map((item) => <li key={item}>{item}</li>)}</ul>
          <strong><KeyRound size={12} /> Signed</strong><p>{agent.signed}</p>
          <strong><ShieldCheck size={12} /> Q-12</strong><p>{agent.q12}</p>
        </div>
      </details>
    </article>
  );
}

function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat("en-GB", {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}
