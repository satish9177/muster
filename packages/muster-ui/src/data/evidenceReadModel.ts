import {
  assertCaseTraceArtifact,
  type ArtifactProposition,
  type ArtifactRelation,
  type ArtifactValue,
  type CaseTraceArtifact,
} from "./caseTraceArtifact";

export const EVIDENCE_PROOF_SCHEMA_VERSION = "muster.evidence-proof/v1" as const;

export interface EvidenceSourceMaterial {
  ref: string;
  file: string;
  mediaType: string;
  delivery: string;
}

interface RawAuditAgent {
  label: string;
  agent_runtime: string;
  capture_status: string;
  source_class?: string;
  source_material: Array<{
    ref: string;
    file: string;
    media_type: string;
    delivery: string;
  }>;
  statement?: string;
  model_receives: string[];
  modalities: string[];
  accepted_candidate: string;
  validation: string[];
  signed: string;
  q12: string;
}

export interface EvidenceProofArtifact {
  schema_version: typeof EVIDENCE_PROOF_SCHEMA_VERSION;
  provenance: {
    source: "committed-milestone-f-path-audit";
    commit: string;
    note: string;
  };
  worker: RawAuditAgent;
  employer: RawAuditAgent & { source_class: string };
  site: RawAuditAgent & { source_class: string };
}

export interface EvidenceAgentViewModel {
  label: string;
  runtime: string;
  captureStatus: string;
  sourceClass: string | null;
  sourceMaterial: EvidenceSourceMaterial[];
  statement: string | null;
  modelReceives: string[];
  modalities: string[];
  acceptedCandidate: string;
  candidateFacts: string[];
  validation: string[];
  signed: string;
  q12: string;
  signerKeys: string[];
  q12Passed: boolean;
}

export interface RaviEvidenceViewModel {
  provenance: EvidenceProofArtifact["provenance"];
  execution: {
    name: string;
    cloudRunRegion: string;
    modelName: string;
    modelLocation: string;
    timestamp: string;
  };
  boundary: {
    actor: string;
    target: string;
    result: string;
    httpStatus: number;
    enforcement: string;
  };
  worker: EvidenceAgentViewModel;
  employer: EvidenceAgentViewModel;
  site: EvidenceAgentViewModel;
  deterministic: {
    outcome: string;
    action: string;
    execution: string;
  };
}

export function transformRaviEvidence(
  traceInput: unknown,
  proofInput: unknown,
): RaviEvidenceViewModel {
  assertCaseTraceArtifact(traceInput);
  assertEvidenceProof(proofInput);

  const trace = traceInput;
  const proof = proofInput;
  const executionName = trace.execution.execution_name;
  const timestamp = trace.execution.executed_at;
  if (!executionName || !timestamp) {
    throw new Error("Ravi Evidence requires a captured cloud execution");
  }

  const workerFact = `${formatProposition(trace.claim.proposition)} = ${formatValue(trace.claim.asserted_value)}`;
  const employerAttestations = attestationsFor(trace, proof.employer.source_class);
  const siteAttestations = attestationsFor(trace, proof.site.source_class);
  if (employerAttestations.length === 0 || siteAttestations.length === 0) {
    throw new Error("Evidence audit does not match captured source classes");
  }

  const recipient = actionField(trace, "recipient");
  const amount = actionField(trace, "amount");
  return {
    provenance: { ...proof.provenance },
    execution: {
      name: executionName,
      cloudRunRegion: trace.execution.cloud_run_region,
      modelName: trace.execution.model.name,
      modelLocation: trace.execution.model.location,
      timestamp,
    },
    boundary: {
      actor: trace.security_boundary.actor,
      target: trace.security_boundary.target_class,
      result: trace.security_boundary.result,
      httpStatus: trace.security_boundary.http_status,
      enforcement: trace.security_boundary.enforcement,
    },
    worker: agentView(proof.worker, [workerFact], [], false),
    employer: agentView(
      proof.employer,
      employerAttestations.map(formatAttestation),
      unique(employerAttestations.map((item) => item.signer_key_ref)),
      employerAttestations.every((item) => item.authorization.status === "PASSED"),
    ),
    site: agentView(
      proof.site,
      siteAttestations.map(formatAttestation),
      unique(siteAttestations.map((item) => item.signer_key_ref)),
      siteAttestations.every((item) => item.authorization.status === "PASSED"),
    ),
    deterministic: {
      outcome: trace.result.outcome,
      action: `${trace.result.action.kind}(${formatValue(recipient)}, ${formatValue(amount)})`,
      execution: trace.result.action.execution.status,
    },
  };
}

function agentView(
  audit: RawAuditAgent,
  candidateFacts: string[],
  signerKeys: string[],
  q12Passed: boolean,
): EvidenceAgentViewModel {
  return {
    label: audit.label,
    runtime: audit.agent_runtime,
    captureStatus: audit.capture_status,
    sourceClass: audit.source_class ?? null,
    sourceMaterial: audit.source_material.map((item) => ({
      ref: item.ref,
      file: item.file,
      mediaType: item.media_type,
      delivery: item.delivery,
    })),
    statement: audit.statement ?? null,
    modelReceives: [...audit.model_receives],
    modalities: [...audit.modalities],
    acceptedCandidate: audit.accepted_candidate,
    candidateFacts,
    validation: [...audit.validation],
    signed: audit.signed,
    q12: audit.q12,
    signerKeys,
    q12Passed,
  };
}

function attestationsFor(trace: CaseTraceArtifact, sourceClass: string) {
  return trace.attestations.filter((item) => item.source_class === sourceClass);
}

function formatAttestation(attestation: CaseTraceArtifact["attestations"][number]): string {
  return `${formatProposition(attestation.proposition)} ${formatRelation(attestation.relation)}`;
}

function formatProposition(value: ArtifactProposition): string {
  return value.args.length ? `${value.predicate}(${value.args.join(",")})` : value.predicate;
}

function formatValue(value: ArtifactValue): string {
  switch (value.type) {
    case "bool":
    case "int":
      return String(value.value);
    case "scaled":
      return `${value.unit} ${(value.minor / 10 ** value.scale).toLocaleString("en-IN")}`;
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

function actionField(trace: CaseTraceArtifact, name: string): ArtifactValue {
  const matches = trace.result.action.fields.filter((field) => field.name === name);
  if (matches.length !== 1) throw new Error(`Captured action requires one ${name} field`);
  return matches[0]!.value;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function assertEvidenceProof(input: unknown): asserts input is EvidenceProofArtifact {
  if (!isRecord(input) || input.schema_version !== EVIDENCE_PROOF_SCHEMA_VERSION) {
    throw new Error("Unsupported MUSTER evidence-proof artifact");
  }
  if (
    !isRecord(input.provenance) ||
    input.provenance.source !== "committed-milestone-f-path-audit" ||
    !isCommit(input.provenance.commit) ||
    !isString(input.provenance.note) ||
    !isAuditAgent(input.worker, false) ||
    !isAuditAgent(input.employer, true) ||
    !isAuditAgent(input.site, true)
  ) {
    throw new Error("Evidence-proof artifact is malformed");
  }
  const site = input.site as RawAuditAgent;
  if (
    !site.source_material.some(
      (item) => item.media_type === "image/png" && item.delivery.includes("inline_data"),
    )
  ) {
    throw new Error("Site evidence proof does not establish the committed image path");
  }
}

function isAuditAgent(value: unknown, requiresClass: boolean): value is RawAuditAgent {
  if (!isRecord(value)) return false;
  return (
    allStrings(value, "label", "agent_runtime", "capture_status", "accepted_candidate", "signed", "q12") &&
    (!requiresClass || isString(value.source_class)) &&
    (value.statement === undefined || isString(value.statement)) &&
    Array.isArray(value.source_material) &&
    value.source_material.length > 0 &&
    value.source_material.every(isSourceMaterial) &&
    stringArray(value.model_receives) &&
    stringArray(value.modalities) &&
    stringArray(value.validation)
  );
}

function isSourceMaterial(value: unknown): boolean {
  return isRecord(value) && allStrings(value, "ref", "file", "media_type", "delivery");
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(isString);
}

function allStrings(value: Record<string, unknown>, ...fields: string[]): boolean {
  return fields.every((field) => isString(value[field]));
}

function isCommit(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{40}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
