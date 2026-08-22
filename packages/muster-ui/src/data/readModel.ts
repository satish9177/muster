export const EVENT_KINDS = [
  "claim",
  "plan",
  "boundary",
  "agent",
  "rebuild",
  "action",
] as const;

export type EventKind = (typeof EVENT_KINDS)[number];
export type ResultTone =
  | "neutral"
  | "denied"
  | "verified"
  | "invariant"
  | "pending"
  | "uncertain"
  | "failed";
export type ReplayMode =
  | "verified-cloud-execution"
  | "deterministic-local-replay"
  | "curated-example";

export interface RawInspectorDetail {
  source_class: string;
  source_identity: string;
  key_id: string | null;
  authority_grant: string;
  predicates: string[];
  disclosure: string;
  q12_result: string;
  model_interpretation: string;
  deterministic_decision: string;
  provenance_note: string;
}

export interface RawTraceEvent {
  id: string;
  sequence: string;
  kind: EventKind;
  actor: string;
  eyebrow: string;
  title: string;
  summary: string;
  result: string;
  result_tone: ResultTone;
  tags: string[];
  http_status?: number;
  inspector: RawInspectorDetail;
}

export interface RawHeroCase {
  schema_version: "muster.hero-case/v1";
  case: {
    id: string;
    title: string;
    subject: string;
    pinned_policy: string;
    policy_version: string;
    status: "PROPOSED";
    outcome: "INVARIANT";
    action: {
      kind: "PAY";
      recipient: string;
      currency: "INR";
      amount_minor: number;
      execution: "NOT_EXECUTED";
    };
    unresolved: string[];
  };
  provenance: {
    mode: ReplayMode;
    label: string;
    description: string;
    basis: string;
    captured_at: string | null;
    capture_available: boolean;
  };
  events: RawTraceEvent[];
}

export interface InspectorDetail {
  sourceClass: string;
  sourceIdentity: string;
  keyId: string | null;
  authorityGrant: string;
  predicates: string[];
  disclosure: string;
  q12Result: string;
  modelInterpretation: string;
  deterministicDecision: string;
  provenanceNote: string;
}

export interface TraceEvent {
  id: string;
  sequence: string;
  kind: EventKind;
  actor: string;
  eyebrow: string;
  title: string;
  summary: string;
  result: string;
  resultTone: ResultTone;
  tags: string[];
  httpStatus: number | null;
  inspector: InspectorDetail;
}

export interface HeroCaseViewModel {
  id: string;
  title: string;
  subject: string;
  pinnedPolicy: string;
  policyVersion: string;
  status: "PROPOSED";
  outcome: "INVARIANT";
  action: {
    kind: "PAY";
    recipient: string;
    amount: string;
    execution: "NOT_EXECUTED";
  };
  unresolved: string[];
  provenance: RawHeroCase["provenance"];
  events: TraceEvent[];
}

const RESULT_TONES = new Set<ResultTone>([
  "neutral",
  "denied",
  "verified",
  "invariant",
  "pending",
  "uncertain",
  "failed",
]);

export function transformHeroCase(input: unknown): HeroCaseViewModel {
  assertHeroCase(input);

  if (
    input.provenance.mode === "verified-cloud-execution" &&
    (!input.provenance.capture_available || !input.provenance.captured_at)
  ) {
    throw new Error("A verified cloud replay must identify its execution capture");
  }
  if (input.provenance.mode === "curated-example" && input.provenance.capture_available) {
    throw new Error("A curated example cannot claim an execution capture");
  }

  const ids = input.events.map((event) => event.id);
  if (new Set(ids).size !== ids.length) {
    throw new Error("Trace event identifiers must be unique");
  }

  const formatter = new Intl.NumberFormat("en-IN", {
    style: "currency",
    currency: input.case.action.currency,
    maximumFractionDigits: 0,
  });

  return {
    id: input.case.id,
    title: input.case.title,
    subject: input.case.subject,
    pinnedPolicy: input.case.pinned_policy,
    policyVersion: input.case.policy_version,
    status: input.case.status,
    outcome: input.case.outcome,
    action: {
      kind: input.case.action.kind,
      recipient: input.case.action.recipient,
      amount: formatter.format(input.case.action.amount_minor / 100),
      execution: input.case.action.execution,
    },
    unresolved: [...input.case.unresolved],
    provenance: { ...input.provenance },
    events: input.events.map((event) => ({
      id: event.id,
      sequence: event.sequence,
      kind: event.kind,
      actor: event.actor,
      eyebrow: event.eyebrow,
      title: event.title,
      summary: event.summary,
      result: event.result,
      resultTone: event.result_tone,
      tags: [...event.tags],
      httpStatus: event.http_status ?? null,
      inspector: {
        sourceClass: event.inspector.source_class,
        sourceIdentity: event.inspector.source_identity,
        keyId: event.inspector.key_id,
        authorityGrant: event.inspector.authority_grant,
        predicates: [...event.inspector.predicates],
        disclosure: event.inspector.disclosure,
        q12Result: event.inspector.q12_result,
        modelInterpretation: event.inspector.model_interpretation,
        deterministicDecision: event.inspector.deterministic_decision,
        provenanceNote: event.inspector.provenance_note,
      },
    })),
  };
}

function assertHeroCase(input: unknown): asserts input is RawHeroCase {
  if (!isRecord(input) || input.schema_version !== "muster.hero-case/v1") {
    throw new Error("Unsupported MUSTER hero-case read model");
  }
  if (!isRecord(input.case) || !isRecord(input.provenance) || !Array.isArray(input.events)) {
    throw new Error("Hero-case read model is incomplete");
  }
  if (!isProvenance(input.provenance)) {
    throw new Error("Hero-case provenance is malformed");
  }
  if (!isRecord(input.case.action) || input.case.action.execution !== "NOT_EXECUTED") {
    throw new Error("UI-1 may only render actions that have not been executed");
  }
  if (
    input.case.status !== "PROPOSED" ||
    input.case.outcome !== "INVARIANT" ||
    input.case.action.kind !== "PAY" ||
    input.case.action.currency !== "INR" ||
    typeof input.case.action.amount_minor !== "number"
  ) {
    throw new Error("Hero-case result does not match the UI-1 contract");
  }
  if (!Array.isArray(input.case.unresolved) || !input.case.unresolved.every(isString)) {
    throw new Error("Hero-case unresolved facts are malformed");
  }
  if (!input.events.every(isTraceEvent)) {
    throw new Error("Hero-case trace is malformed");
  }
}

function isTraceEvent(value: unknown): value is RawTraceEvent {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isString(value.sequence) &&
    EVENT_KINDS.includes(value.kind as EventKind) &&
    isString(value.actor) &&
    isString(value.eyebrow) &&
    isString(value.title) &&
    isString(value.summary) &&
    isString(value.result) &&
    RESULT_TONES.has(value.result_tone as ResultTone) &&
    Array.isArray(value.tags) &&
    value.tags.every(isString) &&
    (value.http_status === undefined || Number.isInteger(value.http_status)) &&
    (value.kind !== "boundary" || Number.isInteger(value.http_status)) &&
    isInspectorDetail(value.inspector)
  );
}

function isProvenance(value: unknown): value is RawHeroCase["provenance"] {
  return (
    isRecord(value) &&
    [
      "verified-cloud-execution",
      "deterministic-local-replay",
      "curated-example",
    ].includes(value.mode as ReplayMode) &&
    isString(value.label) &&
    isString(value.description) &&
    isString(value.basis) &&
    (value.captured_at === null || isString(value.captured_at)) &&
    typeof value.capture_available === "boolean"
  );
}

function isInspectorDetail(value: unknown): value is RawInspectorDetail {
  return (
    isRecord(value) &&
    isString(value.source_class) &&
    isString(value.source_identity) &&
    (value.key_id === null || isString(value.key_id)) &&
    isString(value.authority_grant) &&
    Array.isArray(value.predicates) &&
    value.predicates.every(isString) &&
    isString(value.disclosure) &&
    isString(value.q12_result) &&
    isString(value.model_interpretation) &&
    isString(value.deterministic_decision) &&
    isString(value.provenance_note)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}
