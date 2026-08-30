/**
 * The tracked final Google Cloud Action Gate proof, read fail-closed.
 *
 * This is a **replay of five Cloud Run executions that already happened**. It
 * is not telemetry, nothing here is polled, and no request this viewer makes
 * can change any of it. Three of the four safety claims are typed as literals
 * rather than checked at the edges and then trusted: an artifact that says a
 * real payment happened, or that this is live, or that a Cloud Run process was
 * killed, is not a document this module has a shape for, so the screen cannot
 * render one however the file is edited.
 *
 * The other deliberate choice is `null`. On a control-plane stage a `null`
 * field means *that execution did not report it* — never "false", never
 * "absent from the durable row". The idempotency read reported a state, an
 * external reference and two counters and nothing else; carrying the previous
 * stage's finality forward into it would put a fact on screen that no
 * execution observed.
 */

export const GATE_PROOF_SCHEMA_VERSION = "muster.action-gate-proof/v1" as const;

/** Every durable Gate state this proof is allowed to have observed. */
const PROOF_STATES = ["UNCERTAIN", "CONFIRMED"] as const;
export type ProofState = (typeof PROOF_STATES)[number];

const PROOF_FINALITIES = ["DEFINITELY_EXECUTED", "OUTCOME_UNKNOWN"] as const;
export type ProofFinality = (typeof PROOF_FINALITIES)[number];

const STAGE_IDS = [
  "unknown_after_acceptance",
  "pre_reconciliation_external_read",
  "reconciliation",
  "exact_idempotency_read",
  "final_external_read",
] as const;
export type GateProofStageId = (typeof STAGE_IDS)[number];

/** A durable read of the Gate row by one named Cloud Run execution. */
export interface ControlPlaneStage {
  id: GateProofStageId;
  ordinal: number;
  kind: "control_plane";
  cloudRunExecution: string;
  state: ProofState;
  /** Reported by that execution, or `null` when it reported none. */
  finality: ProofFinality | null;
  outcomeCode: string | null;
  externalReference: string | null;
  reconciledFrom: ProofState | null;
  reconciledAt: number | null;
  dispatches: number;
  inspections: number;
  realFunds: false | null;
}

/** A read-only look at the synthetic external world by one named execution. */
export interface ExternalWorldStage {
  id: GateProofStageId;
  ordinal: number;
  kind: "external_world";
  cloudRunExecution: string;
  attempt: string;
  transferPresent: boolean;
  externalReference: string;
  transferCount: number;
  readOnly: true;
}

export type GateProofStage = ControlPlaneStage | ExternalWorldStage;

export interface GateProofReadModel {
  schemaVersion: typeof GATE_PROOF_SCHEMA_VERSION;
  provenance: {
    projectId: string;
    region: string;
    tenantId: string;
    caseId: string;
    executionId: string;
    /** The commit the deployed image was built from. */
    deployedSourceCommit: string;
    /** The later documentation-only head. It built no image. */
    documentationCommit: string;
    cloudBuildId: string;
    imageDigest: string;
    controlPlaneImage: string;
  };
  claims: {
    sandboxOnly: true;
    realFunds: false;
    liveTelemetry: false;
    cloudRunProcessDeathClaimed: false;
  };
  action: {
    kind: "PAY";
    recipient: string;
    amount: { unit: string; display: string };
  };
  externalReference: string;
  leastPrivilege: {
    cloudRunExecution: string;
    runtimeRole: string;
    runtimeGrants: number;
    privilegeQuestions: number;
    privilegeAnswersWrong: number;
    migrationsApplied: string;
    migrationsCurrent: number[];
  };
  stages: GateProofStage[];
}

export function transformGateProof(input: unknown): GateProofReadModel {
  if (!isRecord(input) || input.schema_version !== GATE_PROOF_SCHEMA_VERSION) {
    throw new Error("Unsupported Action Gate proof record");
  }
  const provenance = input.provenance;
  const claims = input.claims;
  const action = input.action;
  const leastPrivilege = input.least_privilege;
  if (
    !isRecord(provenance) ||
    !isRecord(claims) ||
    !isRecord(action) ||
    !isRecord(leastPrivilege) ||
    !Array.isArray(input.stages)
  ) {
    throw new Error("Action Gate proof record is incomplete");
  }

  //  The four claims are the reason this screen is safe to publish, so a
  //  record that fails to make all four is refused rather than downgraded.
  if (
    claims.sandbox_only !== true ||
    claims.real_funds !== false ||
    claims.live_telemetry !== false ||
    claims.cloud_run_process_death_claimed !== false
  ) {
    throw new Error("Action Gate proof does not assert the sandbox replay claims");
  }

  if (
    !isDigest(provenance.execution_id) ||
    !isCommit(provenance.deployed_source_commit) ||
    !isCommit(provenance.documentation_commit) ||
    !isImageDigest(provenance.image_digest) ||
    !isString(provenance.project_id) ||
    !isString(provenance.region) ||
    !isString(provenance.tenant_id) ||
    !isString(provenance.case_id) ||
    !isString(provenance.cloud_build_id) ||
    !isString(provenance.control_plane_image)
  ) {
    throw new Error("Action Gate proof provenance is malformed");
  }
  //  A proof that names one commit for both fields has lost the distinction
  //  that makes the provenance meaningful, and would let a later docs-only
  //  head be read as the source of the deployed image.
  if (provenance.deployed_source_commit === provenance.documentation_commit) {
    throw new Error("Deployed source and documentation commits must stay distinct");
  }
  if (!provenance.control_plane_image.endsWith(`@${provenance.image_digest}`)) {
    throw new Error("Action Gate proof image does not carry its own digest");
  }

  if (!isString(input.external_reference)) {
    throw new Error("Action Gate proof names no external reference");
  }
  const externalReference = input.external_reference;

  if (
    action.kind !== "PAY" ||
    !isString(action.recipient) ||
    !isRecord(action.amount) ||
    !isString(action.amount.unit) ||
    !isString(action.amount.display)
  ) {
    throw new Error("Action Gate proof action is malformed");
  }

  if (
    !isString(leastPrivilege.cloud_run_execution) ||
    !isString(leastPrivilege.runtime_role) ||
    !isCount(leastPrivilege.runtime_grants) ||
    !isCount(leastPrivilege.privilege_questions) ||
    !isCount(leastPrivilege.privilege_answers_wrong) ||
    !isString(leastPrivilege.migrations_applied) ||
    !Array.isArray(leastPrivilege.migrations_current) ||
    !leastPrivilege.migrations_current.every(isCount)
  ) {
    throw new Error("Action Gate proof least-privilege evidence is malformed");
  }

  const stages = input.stages.map((stage) => transformStage(stage, externalReference));
  assertStageSequence(stages);

  return {
    schemaVersion: GATE_PROOF_SCHEMA_VERSION,
    provenance: {
      projectId: provenance.project_id,
      region: provenance.region,
      tenantId: provenance.tenant_id,
      caseId: provenance.case_id,
      executionId: provenance.execution_id,
      deployedSourceCommit: provenance.deployed_source_commit,
      documentationCommit: provenance.documentation_commit,
      cloudBuildId: provenance.cloud_build_id,
      imageDigest: provenance.image_digest,
      controlPlaneImage: provenance.control_plane_image,
    },
    claims: {
      sandboxOnly: true,
      realFunds: false,
      liveTelemetry: false,
      cloudRunProcessDeathClaimed: false,
    },
    action: {
      kind: "PAY",
      recipient: action.recipient,
      amount: { unit: action.amount.unit, display: action.amount.display },
    },
    externalReference,
    leastPrivilege: {
      cloudRunExecution: leastPrivilege.cloud_run_execution,
      runtimeRole: leastPrivilege.runtime_role,
      runtimeGrants: leastPrivilege.runtime_grants,
      privilegeQuestions: leastPrivilege.privilege_questions,
      privilegeAnswersWrong: leastPrivilege.privilege_answers_wrong,
      migrationsApplied: leastPrivilege.migrations_applied,
      migrationsCurrent: [...leastPrivilege.migrations_current],
    },
    stages,
  };
}

function transformStage(input: unknown, externalReference: string): GateProofStage {
  if (!isRecord(input) || !isStageId(input.id) || !isCount(input.ordinal)) {
    throw new Error("Action Gate proof stage is unidentified");
  }
  if (!isString(input.cloud_run_execution)) {
    throw new Error(`Proof stage ${input.id} names no Cloud Run execution`);
  }

  if (input.kind === "external_world") {
    if (
      !isString(input.attempt) ||
      typeof input.transfer_present !== "boolean" ||
      input.external_reference !== externalReference ||
      !isCount(input.transfer_count) ||
      input.read_only !== true
    ) {
      throw new Error(`External-world stage ${input.id} is malformed or not read-only`);
    }
    return {
      id: input.id,
      ordinal: input.ordinal,
      kind: "external_world",
      cloudRunExecution: input.cloud_run_execution,
      attempt: input.attempt,
      transferPresent: input.transfer_present,
      externalReference,
      transferCount: input.transfer_count,
      readOnly: true,
    };
  }

  if (input.kind !== "control_plane") {
    throw new Error(`Proof stage ${input.id} has an unknown kind`);
  }
  if (
    !isProofState(input.state) ||
    !isFinalityOrNull(input.finality) ||
    !isStringOrNull(input.outcome_code) ||
    !isReferenceOrNull(input.external_reference, externalReference) ||
    !isProofStateOrNull(input.reconciled_from) ||
    !isInstantOrNull(input.reconciled_at) ||
    !isCount(input.dispatches) ||
    !isCount(input.inspections) ||
    (input.real_funds !== false && input.real_funds !== null)
  ) {
    throw new Error(`Control-plane stage ${input.id} is malformed`);
  }
  //  Reconciliation provenance is written as a pair. A lone half is invented.
  if ((input.reconciled_at === null) !== (input.reconciled_from === null)) {
    throw new Error(`Control-plane stage ${input.id} has partial reconciliation provenance`);
  }
  //  An UNCERTAIN row has no settlement to point at; a receipt on one would be
  //  the screen showing an outcome the Gate explicitly did not have.
  if (input.state === "UNCERTAIN" && input.external_reference !== null) {
    throw new Error(`Control-plane stage ${input.id} claims a reference while uncertain`);
  }

  return {
    id: input.id,
    ordinal: input.ordinal,
    kind: "control_plane",
    cloudRunExecution: input.cloud_run_execution,
    state: input.state,
    finality: input.finality,
    outcomeCode: input.outcome_code,
    externalReference: input.external_reference,
    reconciledFrom: input.reconciled_from,
    reconciledAt: input.reconciled_at,
    dispatches: input.dispatches,
    inspections: input.inspections,
    realFunds: input.real_funds,
  };
}

/**
 * The whole point of the proof, checked rather than narrated.
 *
 * One dispatch across the entire sequence, one transfer in the external world
 * at every read, and no dispatch at all after the answer was lost. A record
 * that has drifted out of that shape is refused, because the sentence the
 * screen prints underneath it would no longer be true of the numbers above it.
 */
function assertStageSequence(stages: GateProofStage[]): void {
  const ordinals = stages.map((stage) => stage.ordinal);
  const expected = stages.map((_, index) => index + 1);
  if (ordinals.join() !== expected.join()) {
    throw new Error("Action Gate proof stages are not a contiguous ordered sequence");
  }
  if (new Set(stages.map((stage) => stage.id)).size !== stages.length) {
    throw new Error("Action Gate proof stages repeat an identity");
  }

  const controlPlane = stages.filter(isControlPlaneStage);
  const dispatches = controlPlane.reduce((total, stage) => total + stage.dispatches, 0);
  if (dispatches !== 1) {
    throw new Error(`Action Gate proof records ${dispatches} dispatches, not exactly one`);
  }
  const afterAcceptance = controlPlane.slice(1);
  if (afterAcceptance.some((stage) => stage.dispatches !== 0)) {
    throw new Error("Action Gate proof redispatches after the answer was lost");
  }
  const external = stages.filter(isExternalWorldStage);
  if (external.length === 0 || external.some((stage) => stage.transferCount !== 1)) {
    throw new Error("Action Gate proof does not show exactly one external transfer");
  }
}

export function isControlPlaneStage(stage: GateProofStage): stage is ControlPlaneStage {
  return stage.kind === "control_plane";
}

export function isExternalWorldStage(stage: GateProofStage): stage is ExternalWorldStage {
  return stage.kind === "external_world";
}

/** The one-line summary the footer prints, derived rather than written down. */
export function proofSummary(model: GateProofReadModel): {
  externalEffects: number;
  redispatches: number;
  finalTransferCount: number;
} {
  const controlPlane = model.stages.filter(isControlPlaneStage);
  const external = model.stages.filter(isExternalWorldStage);
  const last = external.at(-1);
  //  `transformGateProof` refuses a record with no external-world read, so
  //  this is unreachable; it is here because an exported helper must not be
  //  the one place that assumes its caller validated first.
  if (!last) throw new Error("Action Gate proof records no external-world read");
  return {
    externalEffects: controlPlane.reduce((total, stage) => total + stage.dispatches, 0),
    redispatches: controlPlane.slice(1).reduce((total, stage) => total + stage.dispatches, 0),
    finalTransferCount: last.transferCount,
  };
}

function isStageId(value: unknown): value is GateProofStageId {
  return STAGE_IDS.includes(value as GateProofStageId);
}

function isProofState(value: unknown): value is ProofState {
  return PROOF_STATES.includes(value as ProofState);
}

function isProofStateOrNull(value: unknown): value is ProofState | null {
  return value === null || isProofState(value);
}

function isFinalityOrNull(value: unknown): value is ProofFinality | null {
  return value === null || PROOF_FINALITIES.includes(value as ProofFinality);
}

function isReferenceOrNull(value: unknown, expected: string): value is string | null {
  return value === null || value === expected;
}

function isInstantOrNull(value: unknown): value is number | null {
  return value === null || (Number.isInteger(value) && (value as number) >= 0);
}

function isCount(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function isDigest(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{64}$/.test(value);
}

function isCommit(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{40}$/.test(value);
}

function isImageDigest(value: unknown): value is string {
  return isString(value) && /^sha256:[0-9a-f]{64}$/.test(value);
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
