import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  CloudCog,
  Eye,
  RefreshCcw,
  Repeat2,
  Send,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useState } from "react";

import { gateProofClient } from "../data/gateProofClient";
import {
  isControlPlaneStage,
  proofSummary,
  type GateProofReadModel,
  type GateProofStage,
  type GateProofStageId,
} from "../data/gateProofReadModel";

/**
 * The judge-facing final Google Cloud Action Gate proof.
 *
 * Every number on this screen is read out of one tracked artifact that records
 * five Cloud Run executions that already finished. Nothing is polled and
 * nothing can be triggered from here, which is why the banner says replay
 * rather than live and why there is no control anywhere in this component.
 *
 * The plain-English copy lives here rather than in the artifact on purpose:
 * the artifact carries only what was observed, and this file carries only how
 * to say it. That way a reviewer can check the facts without reading past the
 * prose, and rewording the prose can never quietly reword a fact.
 */

interface StageCopy {
  icon: LucideIcon;
  headline: string;
  plain: string;
  tone: "dispatched" | "uncertain" | "external" | "reconciled" | "idempotent";
}

const STAGE_COPY: Record<GateProofStageId, StageCopy> = {
  unknown_after_acceptance: {
    icon: Send,
    headline: "DISPATCHED ONCE — THEN THE RESPONSE WAS LOST",
    plain:
      "The sandbox accepted the action once, then its response was deliberately lost. MUSTER records UNCERTAIN instead of guessing or redispatching.",
    tone: "uncertain",
  },
  pre_reconciliation_external_read: {
    icon: Eye,
    headline: "THE EXTERNAL EFFECT ALREADY EXISTS",
    plain:
      "An independent read of the external system, before anything was reconciled, found the transfer already there. Blindly redispatching an uncertain irreversible action can risk a duplicate external effect. MUSTER does not redispatch.",
    tone: "external",
  },
  reconciliation: {
    icon: RefreshCcw,
    headline: "A FRESH PROCESS RECONCILES — IT DOES NOT RETRY",
    plain:
      "A brand-new Cloud Run process looked at the external system, saw the action that already happened, and confirmed the existing MUSTER record. It dispatched nothing.",
    tone: "reconciled",
  },
  exact_idempotency_read: {
    icon: Repeat2,
    headline: "AN EXACT REPEAT REUSES THE RECORD",
    plain:
      "Asking for the very same action again returned the confirmed record. Nothing crossed the external boundary a second time.",
    tone: "idempotent",
  },
  final_external_read: {
    icon: ShieldCheck,
    headline: "THE EXTERNAL WORLD IS STILL UNCHANGED",
    plain:
      "A final independent read of the external system still finds exactly one transfer, with the same reference.",
    tone: "external",
  },
};

export function CloudGateProof() {
  const [model, setModel] = useState<GateProofReadModel | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    gateProofClient
      .load(controller.signal)
      .then(setModel)
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Final Gate proof unavailable");
      });
    return () => controller.abort();
  }, []);

  if (error) {
    return (
      <section className="gate-proof-panel" aria-label="Final Google Cloud Action Gate proof">
        <div className="gate-proof-state">
          <AlertTriangle size={20} aria-hidden="true" />
          <span>{error}</span>
        </div>
      </section>
    );
  }

  if (!model) {
    return (
      <section className="gate-proof-panel" aria-label="Final Google Cloud Action Gate proof">
        <div className="gate-proof-state">
          <CircleDashed size={20} aria-hidden="true" />
          <span>Loading the verified Google Cloud replay…</span>
        </div>
      </section>
    );
  }

  const summary = proofSummary(model);
  return (
    <section className="gate-proof-panel" aria-labelledby="gate-proof-title">
      <header className="gate-proof-header">
        <div className="gate-proof-identity">
          <span className="gate-proof-kicker">
            <CloudCog size={14} aria-hidden="true" /> FINAL GOOGLE CLOUD EXECUTION PROOF
          </span>
          <h2 id="gate-proof-title">
            PAY {model.action.recipient} {model.action.amount.display}
          </h2>
          <p className="gate-proof-sandbox">SANDBOX ONLY · NO REAL FUNDS</p>
        </div>
        <div className="gate-proof-replay-badge">
          <span>VERIFIED GCP REPLAY — NOT LIVE TELEMETRY</span>
          <small>Five finished Cloud Run executions, read from a tracked artifact.</small>
        </div>
      </header>

      <ul className="gate-proof-claims" aria-label="What this proof does and does not claim">
        <li>SANDBOX ONLY</li>
        <li>NO REAL FUNDS</li>
        <li>UNKNOWN AFTER ACCEPTANCE</li>
        <li>CLOUD RUN PROCESS DEATH NOT CLAIMED</li>
      </ul>

      <ol className="gate-proof-timeline" aria-label="Execution proof timeline">
        {model.stages.map((stage) => (
          <ProofStep key={stage.id} stage={stage} />
        ))}
      </ol>

      <div className="gate-proof-result" aria-label="Final proof result">
        <div>
          <CheckCircle2 size={20} aria-hidden="true" />
          <span>ONE EXTERNAL EFFECT</span>
          <strong>{summary.externalEffects}</strong>
        </div>
        <div>
          <span>ZERO REDISPATCH</span>
          <strong>{summary.redispatches}</strong>
        </div>
        <div>
          <span>TRANSFER COUNT STILL 1</span>
          <strong>{summary.finalTransferCount}</strong>
        </div>
      </div>

      <details className="gate-proof-provenance">
        <summary>Immutable build provenance and durable identity</summary>
        <dl>
          <div>
            <dt>Deployed source commit — built and ran this proof</dt>
            <dd><code>{model.provenance.deployedSourceCommit}</code></dd>
          </div>
          <div>
            <dt>Documentation commit — recorded it afterwards, built nothing</dt>
            <dd><code>{model.provenance.documentationCommit}</code></dd>
          </div>
          <div>
            <dt>Cloud Build</dt>
            <dd><code>{model.provenance.cloudBuildId}</code></dd>
          </div>
          <div>
            <dt>Control plane image</dt>
            <dd><code>{model.provenance.controlPlaneImage}</code></dd>
          </div>
          <div>
            <dt>Project / region / tenant</dt>
            <dd>
              {model.provenance.projectId} · {model.provenance.region} ·{" "}
              {model.provenance.tenantId}
            </dd>
          </div>
          <div>
            <dt>Case</dt>
            <dd><code>{model.provenance.caseId}</code></dd>
          </div>
          <div>
            <dt>Durable execution id</dt>
            <dd><code>{model.provenance.executionId}</code></dd>
          </div>
          <div>
            <dt>External reference</dt>
            <dd><code>{model.externalReference}</code></dd>
          </div>
          <div>
            <dt>Runtime least privilege</dt>
            <dd>
              role <code>{model.leastPrivilege.runtimeRole}</code> ·{" "}
              {model.leastPrivilege.runtimeGrants} grants ·{" "}
              {model.leastPrivilege.privilegeQuestions} privilege questions ·{" "}
              {model.leastPrivilege.privilegeAnswersWrong} wrong · verified by{" "}
              <code>{model.leastPrivilege.cloudRunExecution}</code>
            </dd>
          </div>
        </dl>
      </details>
    </section>
  );
}

/**
 * The Action view's own footer.
 *
 * The shared footer names the analysis-only cloud replay the Overview and
 * Evidence views are built from -- one Cloud Run execution, `…-hero-tsjds`.
 * That is the right provenance for those screens and the wrong provenance for
 * this one: the Action view is a different, later proof made of five separate
 * finished executions, and stamping a single unrelated execution name under it
 * would attribute the proof to a run that did not produce it.
 *
 * The count is read from the artifact rather than written here, so this line
 * cannot come to claim a number of executions the proof does not carry.
 */
export function CloudGateProofFooter() {
  const [model, setModel] = useState<GateProofReadModel | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    gateProofClient
      .load(controller.signal)
      .then(setModel)
      .catch(() => setModel(null));
    return () => controller.abort();
  }, []);

  if (!model) return null;
  return (
    <footer className="app-footer">
      <span>
        FINAL GCP ACTION PROOF · {model.stages.length} VERIFIED CLOUD RUN EXECUTIONS ·
        sandbox only · verified replay, not live telemetry
      </span>
      <span>
        {model.provenance.caseId} / execution {model.provenance.executionId}
      </span>
    </footer>
  );
}

function ProofStep({ stage }: { stage: GateProofStage }) {
  const copy = STAGE_COPY[stage.id];
  const Icon = copy.icon;
  return (
    <li className={`gate-proof-step ${copy.tone}`}>
      <span className="gate-proof-ordinal" aria-hidden="true">{stage.ordinal}</span>
      <span className="gate-proof-step-icon" aria-hidden="true"><Icon size={17} /></span>
      <div className="gate-proof-step-body">
        <strong>{copy.headline}</strong>
        <p>{copy.plain}</p>
        <StageFacts stage={stage} />
        <dl className="gate-proof-technical" aria-label="Technical detail">
          {technicalRows(stage).map(([term, value]) => (
            <div key={term}>
              <dt>{term}</dt>
              <dd><code>{value}</code></dd>
            </div>
          ))}
        </dl>
      </div>
    </li>
  );
}

/** The counted facts, in plain words, above the technical vocabulary. */
function StageFacts({ stage }: { stage: GateProofStage }) {
  if (isControlPlaneStage(stage)) {
    return (
      <ul className="gate-proof-facts">
        <li><b>{stage.dispatches}</b> dispatches in this run</li>
        <li><b>{stage.inspections}</b> inspections in this run</li>
        {stage.realFunds === false && <li>real funds: <b>no</b></li>}
      </ul>
    );
  }
  return (
    <ul className="gate-proof-facts">
      <li>transfer {stage.transferPresent ? "present" : "absent"}</li>
      <li>transfer count: <b>{stage.transferCount}</b></li>
      <li>read only — nothing was written</li>
    </ul>
  );
}

/**
 * The secondary technical detail.
 *
 * A field the execution did not report is omitted rather than rendered empty,
 * so the reader never sees a blank that could be mistaken for a `null` the
 * durable row actually held.
 */
function technicalRows(stage: GateProofStage): Array<[string, string]> {
  const rows: Array<[string, string]> = [
    ["Cloud Run execution", stage.cloudRunExecution],
  ];
  if (isControlPlaneStage(stage)) {
    rows.push(["state", stage.state]);
    if (stage.finality) rows.push(["finality", stage.finality]);
    if (stage.outcomeCode) rows.push(["outcome code", stage.outcomeCode]);
    if (stage.reconciledFrom) {
      rows.push(["reconciled_from", stage.reconciledFrom]);
    }
    rows.push(["external reference", stage.externalReference ?? "none"]);
    return rows;
  }
  rows.push(["attempt", stage.attempt]);
  rows.push(["external reference", stage.externalReference]);
  return rows;
}
