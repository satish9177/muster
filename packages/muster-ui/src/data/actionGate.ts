import type { HeroCaseViewModel, ResultTone } from "./readModel";

export const ACTION_GATE_SCHEMA_VERSION = "muster.action-gate-demo/v1" as const;

export const GATE_PHASES = [
  "AUTHORIZED",
  "RESERVED",
  "DISPATCHED",
  "EXECUTED",
  "UNCERTAIN",
  "FAILED",
] as const;

export type GatePhase = (typeof GATE_PHASES)[number];
export type GateLifecycleStep = GatePhase | "CONFIRMED";
export type DurableGateState =
  | "RESERVED"
  | "DISPATCHED"
  | "CONFIRMED"
  | "UNCERTAIN"
  | "FAILED";
export type GateFinality =
  | "DEFINITELY_NOT_EXECUTED"
  | "DEFINITELY_EXECUTED"
  | "OUTCOME_UNKNOWN";

export interface ActionGateReadModel {
  schemaVersion: typeof ACTION_GATE_SCHEMA_VERSION;
  caseId: string;
  proposalId: string;
  proposalStatus: "PROPOSED";
  proposalOutcome: "INVARIANT";
  phase: GatePhase;
  durableState: DurableGateState | null;
  finality: GateFinality;
  executionId: string | null;
  externalReference: string | null;
  lifecycle: GateLifecycleStep[];
  dispatchCount: number;
  automaticRetry: false;
  existingConfirmationReturned: boolean;
  provenance: {
    evidenceAgentPath: "VERIFIED GOOGLE CLOUD EXECUTION REPLAY";
    actionExecution: "LOCAL DETERMINISTIC SANDBOX EXECUTION";
    executionPrincipal: string;
    sandbox: true;
    realFundsTransferred: false;
  };
}

export interface ActionGateClient {
  loadProposal(caseId: string, signal?: AbortSignal): Promise<ActionGateReadModel>;
  execute(caseId: string, proposalId: string): Promise<ActionGateReadModel>;
}

export class HttpActionGateClient implements ActionGateClient {
  constructor(private readonly baseUrl = "/api/demo") {}

  async loadProposal(caseId: string, signal?: AbortSignal): Promise<ActionGateReadModel> {
    return this.request(`${this.baseUrl}/cases/${encodeURIComponent(caseId)}/proposal`, {
      method: "GET",
      signal,
    });
  }

  async execute(caseId: string, proposalId: string): Promise<ActionGateReadModel> {
    return this.request(
      `${this.baseUrl}/cases/${encodeURIComponent(caseId)}/proposals/${encodeURIComponent(proposalId)}/execute`,
      { method: "POST" },
    );
  }

  private async request(url: string, init: RequestInit): Promise<ActionGateReadModel> {
    const response = await fetch(url, init);
    if (!response.ok) {
      throw new Error(`Local sandbox Action Gate refused the request (${response.status})`);
    }
    return transformActionGateReadModel(await response.json());
  }
}

export const actionGateClient: ActionGateClient = new HttpActionGateClient();

export function transformActionGateReadModel(input: unknown): ActionGateReadModel {
  if (!isRecord(input) || input.schema_version !== ACTION_GATE_SCHEMA_VERSION) {
    throw new Error("Unsupported Action Gate read model");
  }
  if (!isString(input.case_id) || !isDigest(input.proposal_id)) {
    throw new Error("Action Gate proposal identity is malformed");
  }
  const proposal = input.proposal;
  const execution = input.execution;
  const provenance = input.provenance;
  if (
    !isRecord(proposal) ||
    proposal.status !== "PROPOSED" ||
    proposal.outcome !== "INVARIANT" ||
    !isRecord(execution) ||
    !isRecord(provenance)
  ) {
    throw new Error("Action Gate proposal/read model is incomplete");
  }
  if (
    !isGatePhase(execution.phase) ||
    !isDurableStateOrNull(execution.durable_state) ||
    !isFinality(execution.finality) ||
    !isStringOrNull(execution.execution_id) ||
    !isStringOrNull(execution.external_reference) ||
    !Array.isArray(execution.lifecycle) ||
    !execution.lifecycle.every(isLifecycleStep) ||
    !Number.isInteger(execution.dispatch_count) ||
    (execution.dispatch_count as number) < 0 ||
    execution.automatic_retry !== false ||
    typeof execution.existing_confirmation_returned !== "boolean"
  ) {
    throw new Error("Action Gate execution state is malformed");
  }
  if (
    provenance.evidence_agent_path !== "VERIFIED GOOGLE CLOUD EXECUTION REPLAY" ||
    provenance.action_execution !== "LOCAL DETERMINISTIC SANDBOX EXECUTION" ||
    !isString(provenance.execution_principal) ||
    provenance.sandbox !== true ||
    provenance.real_funds_transferred !== false
  ) {
    throw new Error("Action Gate provenance is malformed or unsafe");
  }

  const result: ActionGateReadModel = {
    schemaVersion: ACTION_GATE_SCHEMA_VERSION,
    caseId: input.case_id,
    proposalId: input.proposal_id,
    proposalStatus: proposal.status,
    proposalOutcome: proposal.outcome,
    phase: execution.phase,
    durableState: execution.durable_state,
    finality: execution.finality,
    executionId: execution.execution_id,
    externalReference: execution.external_reference,
    lifecycle: [...execution.lifecycle],
    dispatchCount: execution.dispatch_count as number,
    automaticRetry: false,
    existingConfirmationReturned: execution.existing_confirmation_returned,
    provenance: {
      evidenceAgentPath: provenance.evidence_agent_path,
      actionExecution: provenance.action_execution,
      executionPrincipal: provenance.execution_principal,
      sandbox: true,
      realFundsTransferred: false,
    },
  };
  assertStateShape(result);
  return result;
}

export function gateActionLabel(model: ActionGateReadModel): string {
  if (model.phase === "UNCERTAIN" || model.phase === "DISPATCHED") {
    return "Automatic retry disabled";
  }
  if (model.phase === "EXECUTED") return "Read existing confirmation";
  if (model.phase === "FAILED") return "Read existing failure";
  return "Execute sandbox action";
}

export function mayInvokeGate(model: ActionGateReadModel): boolean {
  return model.phase !== "UNCERTAIN" && model.phase !== "DISPATCHED";
}

export function withActionGate(
  model: HeroCaseViewModel,
  gate: ActionGateReadModel | null,
): HeroCaseViewModel {
  if (!gate) return model;
  const description = gateEventDescription(gate);
  return {
    ...model,
    events: model.events.map((event) =>
      event.kind !== "action"
        ? event
        : {
            ...event,
            summary: description.summary,
            result: description.result,
            resultTone: description.tone,
            tags: ["LOCAL SANDBOX", "NO REAL FUNDS"],
            inspector: {
              ...event.inspector,
              sourceClass: "LOCAL DETERMINISTIC ACTION GATE",
              sourceIdentity: gate.provenance.executionPrincipal,
              authorityGrant: "Exact local principal / tenant / action / gate / executor allowlist",
              deterministicDecision: `Gate durable state: ${gate.durableState ?? "NOT RESERVED"}`,
              provenanceNote:
                "Evidence path is the verified cloud replay; execution is the separate local deterministic sandbox.",
            },
          },
    ),
  };
}

function gateEventDescription(model: ActionGateReadModel): {
  result: string;
  summary: string;
  tone: ResultTone;
} {
  switch (model.phase) {
    case "AUTHORIZED":
      return {
        result: "AUTHORIZED · NOT EXECUTED",
        summary: "The exact current proposal is Gate-eligible; no sandbox dispatch has occurred.",
        tone: "pending",
      };
    case "RESERVED":
      return {
        result: "RESERVED",
        summary: "The exact proposal has a durable recoverable reservation.",
        tone: "pending",
      };
    case "DISPATCHED":
      return {
        result: "DISPATCHED · UNKNOWN",
        summary: "The irreversible dispatch boundary is durable; automatic retry is disabled.",
        tone: "uncertain",
      };
    case "EXECUTED":
      return {
        result: "EXECUTED ONCE · SANDBOX",
        summary: model.existingConfirmationReturned
          ? "The existing sandbox confirmation was returned; no second dispatch occurred."
          : "The exact authorized sandbox action was confirmed once.",
        tone: "verified",
      };
    case "UNCERTAIN":
      return {
        result: "UNCERTAIN",
        summary: "Automatic retry is disabled; reconciliation is required.",
        tone: "uncertain",
      };
    case "FAILED":
      return {
        result: "FAILED",
        summary: "The sandbox action definitely did not execute.",
        tone: "failed",
      };
  }
}

function assertStateShape(model: ActionGateReadModel): void {
  if (model.lifecycle[0] !== "AUTHORIZED") {
    throw new Error("Action Gate lifecycle does not begin at authorization");
  }
  switch (model.phase) {
    case "AUTHORIZED":
      if (
        model.durableState !== null ||
        model.executionId !== null ||
        model.externalReference !== null ||
        model.finality !== "DEFINITELY_NOT_EXECUTED"
      ) {
        throw new Error("AUTHORIZED Gate state carries an execution claim");
      }
      break;
    case "RESERVED":
      if (model.durableState !== "RESERVED" || model.finality !== "DEFINITELY_NOT_EXECUTED") {
        throw new Error("RESERVED Gate state has invalid finality");
      }
      break;
    case "DISPATCHED":
      if (model.durableState !== "DISPATCHED" || model.finality !== "OUTCOME_UNKNOWN") {
        throw new Error("DISPATCHED Gate state has invalid finality");
      }
      break;
    case "EXECUTED":
      if (
        model.durableState !== "CONFIRMED" ||
        model.finality !== "DEFINITELY_EXECUTED" ||
        !model.externalReference ||
        model.lifecycle.at(-1) !== "EXECUTED"
      ) {
        throw new Error("EXECUTED Gate state lacks durable confirmation");
      }
      break;
    case "UNCERTAIN":
      if (
        model.durableState !== "UNCERTAIN" ||
        model.finality !== "OUTCOME_UNKNOWN" ||
        model.externalReference !== null
      ) {
        throw new Error("UNCERTAIN Gate state is not reconciliation-safe");
      }
      break;
    case "FAILED":
      if (
        model.durableState !== "FAILED" ||
        model.finality !== "DEFINITELY_NOT_EXECUTED" ||
        model.externalReference !== null
      ) {
        throw new Error("FAILED Gate state has invalid finality");
      }
      break;
  }
}

function isGatePhase(value: unknown): value is GatePhase {
  return GATE_PHASES.includes(value as GatePhase);
}

function isLifecycleStep(value: unknown): value is GateLifecycleStep {
  return value === "CONFIRMED" || isGatePhase(value);
}

function isDurableStateOrNull(value: unknown): value is DurableGateState | null {
  return (
    value === null ||
    ["RESERVED", "DISPATCHED", "CONFIRMED", "UNCERTAIN", "FAILED"].includes(
      value as string,
    )
  );
}

function isFinality(value: unknown): value is GateFinality {
  return ["DEFINITELY_NOT_EXECUTED", "DEFINITELY_EXECUTED", "OUTCOME_UNKNOWN"].includes(
    value as string,
  );
}

function isDigest(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{64}$/.test(value);
}

function isStringOrNull(value: unknown): value is string | null {
  return value === null || isString(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
