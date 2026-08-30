import {
  isActionExecutionState,
  transformHeroCase,
  type ActionExecutionState,
  type HeroCaseViewModel,
  type RawHeroCase,
  type RawTraceEvent,
} from "./readModel";

export const CASE_TRACE_SCHEMA_VERSION = "muster.case-trace/v1" as const;

export type ArtifactProvenanceSource =
  | "verified-cloud-execution"
  | "deterministic-local-replay"
  | "curated-example";

export interface ArtifactProposition {
  predicate: string;
  args: string[];
}

export type ArtifactValue =
  | { type: "bool"; value: boolean }
  | { type: "int"; value: number }
  | { type: "scaled"; unit: string; scale: number; minor: number }
  | { type: "enum"; enum_id: string; value: string };

/**
 * What the artifact says the deterministic Action Gate did.
 *
 * Two shapes, and the discriminant is the only field they share. An
 * analysis-only run publishes the first and carries nothing else, so a screen
 * cannot accidentally read an execution key off a run that never executed. A
 * gate run publishes the second, and `real_funds` is typed as the literal
 * `false`: an artifact claiming a real settlement is not a variant this viewer
 * has, which makes "this screen never shows a real payment" a fact about the
 * type rather than a promise in a comment.
 */
interface ArtifactExecutionCommon {
  execution_key: string;
  real_funds: false;
  /**
   * The durable lifecycle instants, exactly as the execution row carries them.
   * These are measurements, not a reconstructed timeline: the producer read
   * them off the row and this viewer renders them as read.
   *
   * `reserved_at` and `dispatched_at` are always present, because every
   * published state is at or past the dispatch boundary. `finalized_at` is
   * present for exactly the states that have finalized, which the variants
   * below say individually rather than leaving to a nullable field.
   */
  reserved_at: number;
  dispatched_at: number;
}

export type ArtifactActionExecution =
  | { status: "NOT_EXECUTED" }
  //  Dispatched and not yet answered. There is no outcome, no reference and no
  //  finalization instant, because the executor boundary has been crossed and
  //  the executor has not come back -- so all three are `null` in the type
  //  rather than optional in a comment. This is what a real DISPATCHED row
  //  looks like, and the viewer must be able to render one truthfully.
  | (ArtifactExecutionCommon & {
      status: "DISPATCHED";
      external_reference: null;
      outcome_code: null;
      finalized_at: null;
    })
  //  Settled. A confirmed execution has a receipt, and the receipt is the
  //  external reference: a CONFIRMED variant without one is not a shape this
  //  viewer has.
  | (ArtifactExecutionCommon & {
      status: "CONFIRMED";
      external_reference: string;
      outcome_code: string;
      finalized_at: number;
    })
  //  Finalized without a settlement. There is an outcome to report and, by
  //  construction, nothing for a reference to point at.
  | (ArtifactExecutionCommon & {
      status: "FAILED" | "UNCERTAIN";
      external_reference: null;
      outcome_code: string;
      finalized_at: number;
    });

export type ArtifactRelation =
  | { kind: "EXACT" | "CLOSED_LOWER_BOUND" | "CLOSED_UPPER_BOUND"; value: ArtifactValue }
  | { kind: "ENUM_SUBSET"; values: ArtifactValue[] };

export interface CaseTraceArtifact {
  schema_version: typeof CASE_TRACE_SCHEMA_VERSION;
  case_id: string;
  tenant_id: string;
  provenance: {
    source: ArtifactProvenanceSource;
    captured: boolean;
  };
  execution: {
    project_id: string;
    job_name: string;
    execution_name: string | null;
    executed_at: string | null;
    completed_at: string | null;
    cloud_run_region: string;
    model: { name: string; location: string };
  };
  policy: { policy_id: string; bundle_digest: string };
  claim: {
    claimant: string;
    role: string;
    proposition: ArtifactProposition;
    asserted_value: ArtifactValue;
    authority: "CLAIM_ONLY";
  };
  plan: {
    request_id: string;
    requirements: Array<{
      proposition: ArtifactProposition;
      permitted_source_classes: string[];
    }>;
  };
  security_boundary: {
    actor: string;
    operation: string;
    target_class: string;
    result: string;
    http_status: number;
    enforcement: string;
  };
  attestations: Array<{
    agent_id: string;
    source_class: string;
    source_id: string;
    proposition: ArtifactProposition;
    relation: ArtifactRelation;
    signer_key_ref: string;
    entry_digest: string;
    authorization: { check: "Q-12"; status: "PASSED" };
    disclosure_class: string;
    model_interpretation: boolean;
  }>;
  result: {
    status: "PROPOSED";
    outcome: "INVARIANT";
    rebuild: { processor: string; certificate_reproduced: boolean };
    action: {
      kind: "PAY";
      fields: Array<{ name: string; value: ArtifactValue }>;
      execution: ArtifactActionExecution;
    };
    unresolved: ArtifactProposition[];
  };
}

export function transformCaseTraceArtifact(input: unknown): HeroCaseViewModel {
  assertCaseTraceArtifact(input);

  const recipient = actionField(input, "recipient");
  const amount = actionField(input, "amount");
  if (recipient.type !== "enum") throw new Error("PAY recipient must be an enum value");
  if (amount.type !== "scaled" || amount.unit !== "INR" || amount.scale > 2) {
    throw new Error("PAY amount must be an INR scaled value");
  }

  const attestationGroups = groupAttestations(input.attestations);
  const events: RawTraceEvent[] = [
    claimEvent(input),
    planEvent(input),
    boundaryEvent(input),
    ...attestationGroups.map((group, index) => attestationEvent(input, group, index)),
    rebuildEvent(input),
    actionEvent(input, recipient.value, amount),
  ].map((event, index) => ({ ...event, sequence: String(index + 1).padStart(2, "0") }));

  const readModel: RawHeroCase = {
    schema_version: "muster.hero-case/v1",
    case: {
      id: input.case_id,
      title: "Ravi — Saturday Shift Pay",
      subject: recipient.value,
      pinned_policy: "scheduled ∧ present_on_site ∧ duration ≥ 240m ⇒ PAY daily_rate",
      policy_version: `${input.policy.policy_id} · ${input.policy.bundle_digest.slice(0, 12)}`,
      status: input.result.status,
      outcome: input.result.outcome,
      action: {
        kind: input.result.action.kind,
        recipient: recipient.value,
        currency: "INR",
        amount_minor: amount.minor * 10 ** (2 - amount.scale),
        execution: input.result.action.execution.status,
      },
      unresolved: input.result.unresolved.map(formatProposition),
    },
    provenance: provenance(input),
    events,
  };
  return transformHeroCase(readModel);
}

function provenance(artifact: CaseTraceArtifact): RawHeroCase["provenance"] {
  const basis = artifact.execution.execution_name
    ? `${artifact.execution.project_id} / ${artifact.execution.job_name} / ${artifact.execution.execution_name}`
    : `${artifact.execution.project_id} / ${artifact.execution.job_name}`;
  switch (artifact.provenance.source) {
    case "verified-cloud-execution":
      return {
        mode: artifact.provenance.source,
        label: "VERIFIED CLOUD EXECUTION REPLAY",
        description: "Captured real Cloud Run execution replay; this screen is not live telemetry.",
        basis,
        captured_at: artifact.execution.executed_at,
        capture_available: artifact.provenance.captured,
      };
    case "deterministic-local-replay":
      return {
        mode: artifact.provenance.source,
        label: "DETERMINISTIC LOCAL REPLAY",
        description: "Structured local execution replay; this screen is not live telemetry.",
        basis,
        captured_at: artifact.execution.executed_at,
        capture_available: artifact.provenance.captured,
      };
    case "curated-example":
      return {
        mode: artifact.provenance.source,
        label: "CURATED EXAMPLE",
        description: "Development fallback with explanatory data; not execution evidence.",
        basis: "Bundled UI example",
        captured_at: null,
        capture_available: false,
      };
  }
}

function claimEvent(artifact: CaseTraceArtifact): RawTraceEvent {
  const claim = artifact.claim;
  return event({
    id: "claim",
    kind: "claim",
    actor: `${claim.claimant} / ${claim.role}`,
    eyebrow: "Worker claim",
    title: `“${formatProposition(claim.proposition)} = ${formatValue(claim.asserted_value)}”`,
    summary: "The case records the statement. A claim alone creates no authority.",
    result: `${claim.authority.replace("_", " ")} — INERT`,
    result_tone: "neutral",
    tags: [],
    inspector: {
      source_class: "WORKER CLAIM",
      source_identity: claim.claimant,
      key_id: null,
      authority_grant: "None — claimant statements are not justification variants",
      predicates: [`${formatProposition(claim.proposition)} = ${formatValue(claim.asserted_value)} [claimed]`],
      disclosure: "A claimant statement enters the transcript; it does not establish the fact.",
      q12_result: "Not applicable — no attestation",
      model_interpretation: "No — claim replay",
      deterministic_decision: "No — transcript entry only",
      provenance_note: "Claim content is projected from the structured StatementRecord.",
    },
  });
}

function planEvent(artifact: CaseTraceArtifact): RawTraceEvent {
  const requirements = artifact.plan.requirements;
  return event({
    id: "planner",
    kind: "plan",
    actor: "Deterministic planner",
    eyebrow: "Evidence plan",
    title: `${requirements.length} propositions are required`,
    summary: "The planner returns narrow propositions and permitted source classes.",
    result: `REQUIRES ${requirements.length} FACTS`,
    result_tone: "neutral",
    tags: ["DETERMINISTIC"],
    inspector: {
      source_class: "DETERMINISTIC KERNEL",
      source_identity: "Control Plane / evidence planner",
      key_id: null,
      authority_grant: "Policy-pinned planning only; no source access",
      predicates: requirements.map((item) => formatProposition(item.proposition)),
      disclosure: `Request ${artifact.plan.request_id.slice(0, 12)} carries propositions and source classes, not raw evidence.`,
      q12_result: "Not reached — attestations requested",
      model_interpretation: "No",
      deterministic_decision: "Yes — evidence request constructed",
      provenance_note: "The UI displays the producer's plan; it does not derive policy requirements.",
    },
  });
}

function boundaryEvent(artifact: CaseTraceArtifact): RawTraceEvent {
  const boundary = artifact.security_boundary;
  return event({
    id: "boundary",
    kind: "boundary",
    actor: `${boundary.actor} → ${boundary.target_class}`,
    eyebrow: "Security boundary",
    title: "Raw source access refused",
    summary:
      "The Control Plane identity was denied access to Site-A raw evidence by GCP IAM; the Site Agent identity was allowed.",
    result: `${boundary.result} · HTTP ${boundary.http_status} · ${boundary.enforcement}`,
    result_tone: "denied",
    tags: ["OBSERVED EXECUTION EVENT", "NO DISCLOSURE"],
    http_status: boundary.http_status,
    inspector: {
      source_class: "SITE SOURCE BOUNDARY",
      source_identity: boundary.actor,
      key_id: null,
      authority_grant: `GCP IAM denied ${boundary.actor} ${boundary.operation} on Site-A raw evidence`,
      predicates: [`${boundary.operation}(${boundary.target_class}) = ${boundary.result}`],
      disclosure: `Observed HTTP ${boundary.http_status}: GCP IAM refused the Control Plane request for Site-A raw evidence.`,
      q12_result: "Not applicable — denial precedes attestation",
      model_interpretation: "No model client in the Control Plane",
      deterministic_decision: `No — ${boundary.enforcement} enforced the boundary`,
      provenance_note: "The status shown here comes from the execution artifact, not a frontend constant.",
    },
  });
}

type Attestation = CaseTraceArtifact["attestations"][number];

function groupAttestations(attestations: Attestation[]): Attestation[][] {
  const groups = new Map<string, Attestation[]>();
  for (const attestation of attestations) {
    const group = groups.get(attestation.agent_id) ?? [];
    group.push(attestation);
    groups.set(attestation.agent_id, group);
  }
  return [...groups.values()];
}

function attestationEvent(
  artifact: CaseTraceArtifact,
  attestations: Attestation[],
  index: number,
): RawTraceEvent {
  const first = attestations[0];
  if (!first) throw new Error("Attestation group cannot be empty");
  const interpreted = attestations.some((item) => item.model_interpretation);
  const predicates = attestations.map(
    (item) => `${formatProposition(item.proposition)} ${formatRelation(item.relation)}`,
  );
  return event({
    id: `agent-${index + 1}`,
    kind: "agent",
    actor: first.agent_id,
    eyebrow: `Institutional source · ${first.source_class}`,
    title: predicates.join("; "),
    summary: "The source returned narrow signed relations; source material stayed local.",
    result: `${attestations.length} SIGNED · Q-12 PASSED`,
    result_tone: "verified",
    tags: [artifact.execution.model.name, "NARROW ATTESTATION"],
    inspector: {
      source_class: first.source_class,
      source_identity: `${first.source_id} / ${first.agent_id}`,
      key_id: [...new Set(attestations.map((item) => item.signer_key_ref))].join(", "),
      authority_grant: `${[...new Set(attestations.map((item) => item.disclosure_class))].join(", ")} disclosure`,
      predicates,
      disclosure: "Only authorized relations and safe provenance crossed the source boundary.",
      q12_result: `PASSED ×${attestations.length} — signer, scope, predicate, validity`,
      model_interpretation: interpreted
        ? `Yes — ${artifact.execution.model.name} in ${artifact.execution.model.location}`
        : "No",
      deterministic_decision: "No — the source interprets and attests",
      provenance_note: `Admission digests: ${attestations.map((item) => item.entry_digest.slice(0, 12)).join(", ")}`,
    },
  });
}

function rebuildEvent(artifact: CaseTraceArtifact): RawTraceEvent {
  const unresolved = artifact.result.unresolved.map(formatProposition);
  return event({
    id: "rebuild",
    kind: "rebuild",
    actor: "Deterministic kernel",
    eyebrow: "Case rebuild",
    title: "Authorized facts entail one outcome",
    summary: "Unresolved facts remain, but every policy-consistent world yields the same action.",
    result: artifact.result.outcome,
    result_tone: "invariant",
    tags: [artifact.result.rebuild.processor, "UNRESOLVED FACTS RETAINED"],
    inspector: {
      source_class: "DETERMINISTIC KERNEL",
      source_identity: "Control Plane / rebuild",
      key_id: null,
      authority_grant: "Admitted transcript entries only",
      predicates: [`outcome = ${artifact.result.outcome}`, ...unresolved.map((item) => `${item} = unresolved`)],
      disclosure: "The artifact carries the outcome and unresolved references, not source material.",
      q12_result: `PASSED on all ${artifact.attestations.length} admitted attestations`,
      model_interpretation: "No — models cannot decide or authorize",
      deterministic_decision: `processor: ${artifact.result.rebuild.processor}; certificate_reproduced: ${artifact.result.rebuild.certificate_reproduced}`,
      provenance_note: "The UI receives the rebuilt result and does not recompute policy semantics.",
    },
  });
}

const EXECUTION_TONES: Record<
  Exclude<ActionExecutionState, "NOT_EXECUTED">,
  RawTraceEvent["result_tone"]
> = {
  CONFIRMED: "verified",
  DISPATCHED: "uncertain",
  UNCERTAIN: "uncertain",
  FAILED: "failed",
};

function actionEvent(
  artifact: CaseTraceArtifact,
  recipient: string,
  amount: Extract<ArtifactValue, { type: "scaled" }>,
): RawTraceEvent {
  const execution = artifact.result.action.execution;
  const proposed = `proposed_action = ${artifact.result.action.kind}(${recipient}, ${formatValue(amount)})`;
  if (execution.status === "NOT_EXECUTED") {
    return event({
      id: "action",
      kind: "action",
      actor: "Proposed action",
      eyebrow: "Authorization handoff",
      title: `${artifact.result.action.kind} ${recipient} ${formatValue(amount)}`,
      //  The single most misreadable line on this screen. This artifact is the
      //  earlier analysis-only cloud run, which stopped at the proposal and
      //  never opened the Gate -- and a reader who takes "NOT EXECUTED" as the
      //  system's final answer has drawn the opposite conclusion from the one
      //  the evidence supports. So the sentence names which run this is, and
      //  points at the separate, finished execution proof.
      summary:
        "This analysis-only cloud run stopped at the proposal and never opened the Action Gate. " +
        "The separate final Google Cloud execution proof is in the Action view of this case.",
      result: "NOT EXECUTED IN THIS RUN",
      result_tone: "pending",
      tags: ["ANALYSIS-ONLY RUN", "GATE NOT OPENED HERE"],
      inspector: {
        source_class: "DETERMINISTIC CASE RESULT",
        source_identity: "MUSTER Control Plane",
        key_id: null,
        authority_grant: "No execution grant in the captured cloud replay",
        predicates: [proposed],
        disclosure: "A proposed consequential action, explicitly not a settlement receipt.",
        q12_result: "Source authority validated upstream",
        model_interpretation: "No",
        deterministic_decision: `Yes — proposed from ${artifact.result.outcome} analysis`,
        provenance_note:
          "This run's action state is NOT_EXECUTED because it is the analysis-only capture. " +
          "It is not the final cloud state: the final Gate proof is a separate case and execution.",
      },
    });
  }
  //  Every line below is a field the Gate produced. The lifecycle is written
  //  out in full because the states it passed through are what the screen is
  //  claiming, and a summary that said "executed" without them would be the
  //  viewer asserting a sequence the artifact does not carry.
  //
  //  DISPATCHED is where the machine currently *is*, not where it ended, so the
  //  explanatory path stops at it rather than naming it twice. A tag reading
  //  `DISPATCHED → DISPATCHED` would draw an edge the Gate does not have, on
  //  the one row whose next state is genuinely still open.
  const path =
    execution.status === "DISPATCHED"
      ? "PROPOSED → RESERVED → DISPATCHED"
      : `PROPOSED → RESERVED → DISPATCHED → ${execution.status}`;
  //  What a dispatched row is allowed to say about its result, which is
  //  nothing. `external_reference = none` is a *finding*: it is what FAILED and
  //  UNCERTAIN report, because those rows finalized and there was no receipt to
  //  record. A row the executor has not answered has found nothing, and
  //  printing `none` for it would publish a settled absence in place of an open
  //  question -- the same overclaim as an invented outcome code. So both result
  //  fields are absent for DISPATCHED, and not knowing is named instead.
  const result_fields =
    execution.status === "DISPATCHED"
      ? ["finality = OUTCOME_UNKNOWN"]
      : [
          `external_reference = ${execution.external_reference ?? "none"}`,
          `outcome_code = ${execution.outcome_code}`,
        ];
  return event({
    id: "action",
    kind: "action",
    actor: "Cloud deterministic Action Gate",
    eyebrow: "Authorized execution",
    title: `${artifact.result.action.kind} ${recipient} ${formatValue(amount)}`,
    summary:
      execution.status === "CONFIRMED"
        ? "The exact authorized action was reserved, dispatched once, and confirmed. A retry reads this record; it does not dispatch again."
        : execution.status === "DISPATCHED"
          ? "The exact authorized action was reserved and dispatched once, and the executor has not answered. There is no outcome yet. A retry reads this record; it does not dispatch again."
          : "The durable lifecycle crossed the dispatch boundary and stopped here. Automatic retry is disabled.",
    result: `${execution.status} · SANDBOX · NO REAL FUNDS`,
    result_tone: EXECUTION_TONES[execution.status],
    //  The first tag is the state machine and is labelled as such; the second
    //  is what the row actually says. Keeping them apart is the whole point:
    //  a CONFIRMED row does imply it passed through RESERVED and DISPATCHED,
    //  but that is an explanation of the machine, while the instants below are
    //  values the database recorded.
    tags: [`STATE MACHINE: ${path}`, `RECORDED: ${execution.status}`, "NO REAL FUNDS"],
    inspector: {
      source_class: "CLOUD DETERMINISTIC ACTION GATE",
      source_identity: "MUSTER Control Plane / Cloud SQL execution custody",
      key_id: execution.execution_key.slice(0, 16),
      authority_grant: "Exact runtime principal / tenant / action / gate / executor grant",
      predicates: [
        proposed,
        `execution_key = ${execution.execution_key}`,
        `state = ${execution.status}`,
        `reserved_at = ${execution.reserved_at}`,
        `dispatched_at = ${execution.dispatched_at}`,
        `finalized_at = ${execution.finalized_at ?? "not finalized"}`,
        ...result_fields,
        `real_funds = ${String(execution.real_funds)}`,
      ],
      disclosure: "A synthetic sandbox execution reference. No payment provider was called and no funds moved.",
      q12_result: "Source authority validated upstream; execution authority is a separate grant",
      model_interpretation: "No — no model can reach the Gate",
      deterministic_decision: `Durable execution state: ${execution.status}`,
      provenance_note: "Every execution field above is a value read from the durable Cloud SQL row the captured execution wrote; the state-machine path in the first tag is an explanation of the Gate, not a recorded sequence of events.",
    },
  });
}

function event(value: Omit<RawTraceEvent, "sequence">): RawTraceEvent {
  return { ...value, sequence: "" };
}

function actionField(artifact: CaseTraceArtifact, name: string): ArtifactValue {
  const matches = artifact.result.action.fields.filter((field) => field.name === name);
  if (matches.length !== 1) throw new Error(`PAY action requires exactly one ${name} field`);
  return matches[0]!.value;
}

function formatProposition(value: ArtifactProposition): string {
  return value.args.length > 0 ? `${value.predicate}(${value.args.join(", ")})` : value.predicate;
}

function formatValue(value: ArtifactValue): string {
  switch (value.type) {
    case "bool":
      return String(value.value);
    case "int":
      return String(value.value);
    case "scaled": {
      const numeric = value.minor / 10 ** value.scale;
      return `${value.unit} ${numeric.toLocaleString("en-IN", { maximumFractionDigits: value.scale })}`;
    }
    case "enum":
      return value.value;
  }
}

function formatRelation(relation: ArtifactRelation): string {
  switch (relation.kind) {
    case "EXACT":
      return `= ${formatValue(relation.value)}`;
    case "CLOSED_LOWER_BOUND":
      return `≥ ${formatValue(relation.value)}`;
    case "CLOSED_UPPER_BOUND":
      return `≤ ${formatValue(relation.value)}`;
    case "ENUM_SUBSET":
      return `∈ {${relation.values.map(formatValue).join(", ")}}`;
  }
}


function assertActionExecution(execution: Record<string, unknown>): void {
  //  The state is validated before the shape, so that `status` narrows to the
  //  published vocabulary for everything below -- and so that RESERVED, which
  //  is deliberately not in it, is refused as a state rather than as a set of
  //  missing fields.
  const status = execution.status;
  if (!isActionExecutionState(status)) {
    throw new Error("Case-trace action execution names an unknown state");
  }
  if (status === "NOT_EXECUTED") {
    if (Object.keys(execution).length !== 1) {
      throw new Error("An unexecuted action carries no execution fields");
    }
    return;
  }
  //  Exactly false, not merely falsy. This is the field the whole screen is
  //  honest by, and 0, null and the empty string must not satisfy it.
  if (execution.real_funds !== false) {
    throw new Error("This viewer never renders a real-funds execution");
  }
  if (
    typeof execution.execution_key !== "string" ||
    !/^[0-9a-f]{64}$/.test(execution.execution_key)
  ) {
    throw new Error("Case-trace action execution names no canonical execution key");
  }
  //  DISPATCHED is the one published state that has no result yet, so it is
  //  the one state whose outcome code must be absent. Demanding a code from
  //  every state made a truthful dispatched row unrenderable, and the only way
  //  to satisfy that demand was to invent one -- `outcome_code: "DISPATCHED"`,
  //  a lifecycle state presented to an audience as a result.
  if (status === "DISPATCHED") {
    if (execution.outcome_code !== null) {
      throw new Error("A dispatched execution has no outcome yet");
    }
  } else if (
    typeof execution.outcome_code !== "string" ||
    execution.outcome_code.length === 0
  ) {
    throw new Error("A finalized execution carries an outcome code");
  }
  const reference = execution.external_reference;
  if (status === "CONFIRMED") {
    if (typeof reference !== "string" || reference.length === 0) {
      throw new Error("A confirmed execution carries an external reference");
    }
  } else if (reference !== null) {
    throw new Error("An unconfirmed execution carries no external reference");
  }
  assertLifecycleInstants(execution, status);
}

/**
 * The three durable instants the row carries, checked as measurements.
 *
 * `typeof x === "number"` is not enough on its own here: `NaN` is a number and
 * would render as "NaN" in a field the screen presents as a recorded moment, so
 * `Number.isInteger` is the predicate. A viewer that displayed an instant it
 * could not verify would be showing an audience something it made up.
 */
function assertLifecycleInstants(
  execution: Record<string, unknown>,
  status: Exclude<ActionExecutionState, "NOT_EXECUTED">,
): void {
  const instant = (name: string): number => {
    const value = execution[name];
    if (!Number.isInteger(value)) {
      throw new Error(`Case-trace execution ${name} is not a durable instant`);
    }
    return value as number;
  };
  const reserved = instant("reserved_at");
  const dispatched = instant("dispatched_at");
  //  Every published state is at or past DISPATCHED, so only the finalization
  //  is optional -- and it is optional for exactly one state.
  const finalized = execution.finalized_at;
  if (status === "DISPATCHED") {
    if (finalized !== null) {
      throw new Error("A dispatched execution has not been finalized");
    }
  } else {
    const settled = instant("finalized_at");
    if (settled < dispatched) {
      throw new Error("Finalization cannot precede dispatch");
    }
  }
  if (dispatched < reserved) {
    throw new Error("Dispatch cannot precede reservation");
  }
}

export function assertCaseTraceArtifact(input: unknown): asserts input is CaseTraceArtifact {
  if (!isRecord(input) || input.schema_version !== CASE_TRACE_SCHEMA_VERSION) {
    throw new Error("Unsupported MUSTER case-trace artifact");
  }
  requireStrings(input, "case_id", "tenant_id");
  const provenanceValue = record(input.provenance, "provenance");
  if (!isProvenanceSource(provenanceValue.source) || typeof provenanceValue.captured !== "boolean") {
    throw new Error("Case-trace provenance is malformed");
  }
  const execution = record(input.execution, "execution");
  requireStrings(execution, "project_id", "job_name", "cloud_run_region");
  nullableString(execution.execution_name, "execution_name");
  nullableString(execution.executed_at, "executed_at");
  nullableString(execution.completed_at, "completed_at");
  const model = record(execution.model, "execution.model");
  requireStrings(model, "name", "location");
  if (
    provenanceValue.source === "verified-cloud-execution" &&
    (!provenanceValue.captured || !execution.execution_name || !execution.executed_at || !execution.completed_at)
  ) {
    throw new Error("Verified cloud artifact is not bound to an execution capture");
  }
  if (provenanceValue.source === "curated-example" && provenanceValue.captured) {
    throw new Error("A curated artifact cannot claim an execution capture");
  }

  const policy = record(input.policy, "policy");
  requireStrings(policy, "policy_id", "bundle_digest");
  const claim = record(input.claim, "claim");
  requireStrings(claim, "claimant", "role");
  if (claim.authority !== "CLAIM_ONLY" || !isProposition(claim.proposition) || !isValue(claim.asserted_value)) {
    throw new Error("Case-trace claim is malformed");
  }
  const plan = record(input.plan, "plan");
  requireStrings(plan, "request_id");
  if (!Array.isArray(plan.requirements) || !plan.requirements.every(isRequirement)) {
    throw new Error("Case-trace plan is malformed");
  }
  const boundary = record(input.security_boundary, "security_boundary");
  requireStrings(boundary, "actor", "operation", "target_class", "result", "enforcement");
  if (!Number.isInteger(boundary.http_status)) throw new Error("Case-trace boundary is malformed");
  if (
    provenanceValue.source === "verified-cloud-execution" &&
    (boundary.result !== "DENIED" || boundary.http_status !== 403)
  ) {
    throw new Error("Verified cloud artifact does not carry the observed IAM 403");
  }
  if (!Array.isArray(input.attestations) || input.attestations.length === 0 || !input.attestations.every(isAttestation)) {
    throw new Error("Case-trace attestations are malformed");
  }
  const result = record(input.result, "result");
  if (result.status !== "PROPOSED" || result.outcome !== "INVARIANT") {
    throw new Error("Case-trace result is outside the hero viewer contract");
  }
  const rebuild = record(result.rebuild, "result.rebuild");
  requireStrings(rebuild, "processor");
  if (typeof rebuild.certificate_reproduced !== "boolean") throw new Error("Case-trace rebuild is malformed");
  const action = record(result.action, "result.action");
  if (
    action.kind !== "PAY" ||
    !Array.isArray(action.fields) ||
    !action.fields.every(isActionField)
  ) {
    throw new Error("Case-trace action is malformed or unsafe");
  }
  assertActionExecution(record(action.execution, "result.action.execution"));
  if (!Array.isArray(result.unresolved) || !result.unresolved.every(isProposition)) {
    throw new Error("Case-trace unresolved propositions are malformed");
  }
}

function isRequirement(value: unknown): boolean {
  if (!isRecord(value) || !isProposition(value.proposition)) return false;
  return Array.isArray(value.permitted_source_classes) && value.permitted_source_classes.every(isString);
}

function isAttestation(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (!allStrings(value, "agent_id", "source_class", "source_id", "signer_key_ref", "entry_digest", "disclosure_class")) return false;
  const authorization = value.authorization;
  return (
    isProposition(value.proposition) &&
    isRelation(value.relation) &&
    isRecord(authorization) &&
    authorization.check === "Q-12" &&
    authorization.status === "PASSED" &&
    typeof value.model_interpretation === "boolean"
  );
}

function isActionField(value: unknown): boolean {
  return isRecord(value) && isString(value.name) && isValue(value.value);
}

function isProposition(value: unknown): value is ArtifactProposition {
  return isRecord(value) && isString(value.predicate) && Array.isArray(value.args) && value.args.every(isString);
}

function isRelation(value: unknown): value is ArtifactRelation {
  if (!isRecord(value) || !isString(value.kind)) return false;
  if (value.kind === "ENUM_SUBSET") return Array.isArray(value.values) && value.values.every(isValue);
  return ["EXACT", "CLOSED_LOWER_BOUND", "CLOSED_UPPER_BOUND"].includes(value.kind) && isValue(value.value);
}

function isValue(value: unknown): value is ArtifactValue {
  if (!isRecord(value)) return false;
  switch (value.type) {
    case "bool":
      return typeof value.value === "boolean";
    case "int":
      return Number.isInteger(value.value);
    case "scaled":
      return isString(value.unit) && Number.isInteger(value.scale) && Number.isInteger(value.minor) && (value.scale as number) >= 0;
    case "enum":
      return isString(value.enum_id) && isString(value.value);
    default:
      return false;
  }
}

function isProvenanceSource(value: unknown): value is ArtifactProvenanceSource {
  return ["verified-cloud-execution", "deterministic-local-replay", "curated-example"].includes(value as string);
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${name} must be an object`);
  return value;
}

function requireStrings(value: Record<string, unknown>, ...fields: string[]): void {
  if (!allStrings(value, ...fields)) throw new Error(`Mandatory string field missing: ${fields.join(", ")}`);
}

function allStrings(value: Record<string, unknown>, ...fields: string[]): boolean {
  return fields.every((field) => isString(value[field]) && (value[field] as string).length > 0);
}

function nullableString(value: unknown, name: string): void {
  if (value !== null && !isString(value)) throw new Error(`${name} must be a string or null`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}
