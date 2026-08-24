interface DurableState {
  status: "AWAITING_EVIDENCE" | "PROPOSED";
  outcome: "DIVERGENT" | "INVARIANT";
  head: {
    revision_number: number;
    revision_digest: string;
    certificate_digest: string;
    transcript_prefix_digest: string;
  };
  transcript_entry_count: number;
  outstanding_request_count: number;
}

interface DurableResult {
  status: "PROPOSED";
  outcome: "INVARIANT";
  exact_duration_status: "UNRESOLVED";
  action: {
    kind: "PAY";
    recipient: string;
    amount: { display: string };
    display: string;
  };
  execution: "NOT_EXECUTED";
}

interface DurableEvidence {
  proposition: { display: string };
  source_class: string;
  authorization: "Q-12";
  relation: { kind: "EXACT" | "CLOSED_LOWER_BOUND"; display: string };
}

export interface AsyncDurabilityReadModel {
  schema_version: "muster.async-durability/v1";
  provenance: {
    source: "local-postgresql-durability-proof";
    label: "LOCAL POSTGRESQL DURABILITY PROOF";
    environment: "SYNTHETIC_DEMO";
    cloud_execution: false;
    note: string;
  };
  case: { tenant_id: string; case_id: string };
  events: [
    {
      phase: "EMPLOYER";
      label: "T0";
      process_id: number;
      state: DurableState;
      employer_entry_present: true;
      delivered: DurableEvidence[];
    },
    {
      phase: "RESUME_SITE";
      label: "LATER_EVENT";
      process_id: number;
      loaded_state: DurableState;
      state: DurableState;
      prior_employer_entry_preserved: true;
      delivered: DurableEvidence[];
      result: DurableResult;
    },
  ];
  continuity: {
    same_tenant_case: true;
    different_processes: true;
    loaded_phase_one_head: true;
    loaded_phase_one_transcript: true;
    prior_employer_evidence_preserved: true;
    revision_progressed: true;
  };
  result: DurableResult;
}

export function parseAsyncDurability(input: unknown): AsyncDurabilityReadModel {
  if (!isRecord(input) || input.schema_version !== "muster.async-durability/v1") {
    throw new Error("Unsupported MUSTER async durability proof");
  }
  const events = input.events;
  if (
    !isProvenance(input.provenance) ||
    !isIdentity(input.case) ||
    !Array.isArray(events) ||
    events.length !== 2 ||
    !isEmployer(events[0]) ||
    !isResume(events[1]) ||
    !isContinuity(input.continuity) ||
    !isResult(input.result)
  ) throw new Error("Async durability proof is malformed");
  if (
    events[0].process_id === events[1].process_id ||
    events[0].state.head.revision_digest !== events[1].loaded_state.head.revision_digest ||
    events[0].state.head.transcript_prefix_digest !==
      events[1].loaded_state.head.transcript_prefix_digest ||
    events[1].state.head.revision_number <= events[0].state.head.revision_number
  ) throw new Error("Async durability continuity proof is inconsistent");
  return input as unknown as AsyncDurabilityReadModel;
}

function isEmployer(value: unknown): value is AsyncDurabilityReadModel["events"][0] {
  return isRecord(value) && value.phase === "EMPLOYER" && value.label === "T0" &&
    Number.isInteger(value.process_id) && value.employer_entry_present === true &&
    isEvidenceList(value.delivered) && isState(value.state);
}

function isResume(value: unknown): value is AsyncDurabilityReadModel["events"][1] {
  return isRecord(value) && value.phase === "RESUME_SITE" && value.label === "LATER_EVENT" &&
    Number.isInteger(value.process_id) && value.prior_employer_entry_preserved === true &&
    isEvidenceList(value.delivered) && isState(value.loaded_state) &&
    isState(value.state) && isResult(value.result);
}

function isEvidenceList(value: unknown): value is DurableEvidence[] {
  return Array.isArray(value) && value.length > 0 && value.every((item) =>
    isRecord(item) && item.authorization === "Q-12" && typeof item.source_class === "string" &&
    isRecord(item.proposition) && typeof item.proposition.display === "string" &&
    isRecord(item.relation) &&
    (item.relation.kind === "EXACT" || item.relation.kind === "CLOSED_LOWER_BOUND") &&
    typeof item.relation.display === "string"
  );
}

function isState(value: unknown): value is DurableState {
  return isRecord(value) &&
    (value.status === "AWAITING_EVIDENCE" || value.status === "PROPOSED") &&
    (value.outcome === "DIVERGENT" || value.outcome === "INVARIANT") &&
    Number.isInteger(value.transcript_entry_count) &&
    Number.isInteger(value.outstanding_request_count) && isHead(value.head);
}

function isHead(value: unknown): boolean {
  return isRecord(value) && Number.isInteger(value.revision_number) &&
    strings(value, "revision_digest", "certificate_digest", "transcript_prefix_digest") &&
    [value.revision_digest, value.certificate_digest, value.transcript_prefix_digest]
      .every((digest) => typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest));
}

function isResult(value: unknown): value is DurableResult {
  return isRecord(value) && value.status === "PROPOSED" && value.outcome === "INVARIANT" &&
    value.exact_duration_status === "UNRESOLVED" && value.execution === "NOT_EXECUTED" &&
    isRecord(value.action) && value.action.kind === "PAY" &&
    strings(value.action, "recipient", "display") && isRecord(value.action.amount) &&
    typeof value.action.amount.display === "string";
}

function isContinuity(value: unknown): boolean {
  return isRecord(value) && ["same_tenant_case", "different_processes", "loaded_phase_one_head",
    "loaded_phase_one_transcript", "prior_employer_evidence_preserved", "revision_progressed"]
    .every((key) => value[key] === true);
}

function isProvenance(value: unknown): boolean {
  return isRecord(value) && value.source === "local-postgresql-durability-proof" &&
    value.label === "LOCAL POSTGRESQL DURABILITY PROOF" &&
    value.environment === "SYNTHETIC_DEMO" && value.cloud_execution === false &&
    typeof value.note === "string";
}

function isIdentity(value: unknown): boolean {
  return isRecord(value) && strings(value, "tenant_id", "case_id");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function strings(value: Record<string, unknown>, ...keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === "string");
}
