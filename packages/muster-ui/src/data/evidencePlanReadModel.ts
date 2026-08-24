export interface EvidencePlanItem {
  label: string;
  proposition: { predicate: string; args: string[]; display: string };
  status: "RESOLVED";
  requirement: string;
  established: string;
  reason: string;
}

export interface EvidencePlanReadModel {
  schema_version: "muster.evidence-plan/v1";
  case: { tenant_id: string; case_id: string };
  required_resolved: EvidencePlanItem[];
  not_required: Array<{
    label: string;
    proposition: EvidencePlanItem["proposition"];
    status: "NOT_REQUIRED";
    unresolved: true;
    reason: string;
  }>;
  summary: {
    reachable_action_count: number;
    outcome: "INVARIANT";
    exact_duration_status: "UNRESOLVED";
    action: {
      kind: string;
      fields: Record<string, { display: string }>;
      display: string;
    };
    explanation: string;
  };
  provenance: {
    mode: "verified-cloud-execution-projection";
    label: "VERIFIED CLOUD EXECUTION";
    description: string;
    basis: string;
  };
}

export function parseEvidencePlan(input: unknown): EvidencePlanReadModel {
  if (!isRecord(input) || input.schema_version !== "muster.evidence-plan/v1") {
    throw new Error("Unsupported MUSTER evidence-plan read model");
  }
  if (
    !isIdentity(input.case) ||
    !Array.isArray(input.required_resolved) ||
    input.required_resolved.length === 0 ||
    !input.required_resolved.every(isRequiredItem) ||
    !Array.isArray(input.not_required) ||
    input.not_required.length === 0 ||
    !input.not_required.every(isNotRequiredItem) ||
    !isSummary(input.summary) ||
    !isProvenance(input.provenance)
  ) {
    throw new Error("Evidence-plan read model is malformed");
  }
  return input as unknown as EvidencePlanReadModel;
}

function isRequiredItem(value: unknown): value is EvidencePlanItem {
  return (
    isRecord(value) &&
    value.status === "RESOLVED" &&
    isProposition(value.proposition) &&
    strings(value, "label", "requirement", "established", "reason")
  );
}

function isNotRequiredItem(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.status === "NOT_REQUIRED" &&
    value.unresolved === true &&
    isProposition(value.proposition) &&
    strings(value, "label", "reason")
  );
}

function isSummary(value: unknown): boolean {
  if (
    !isRecord(value) ||
    !Number.isInteger(value.reachable_action_count) ||
    value.outcome !== "INVARIANT" ||
    value.exact_duration_status !== "UNRESOLVED" ||
    typeof value.explanation !== "string" ||
    !isRecord(value.action) ||
    typeof value.action.kind !== "string" ||
    typeof value.action.display !== "string" ||
    !isRecord(value.action.fields)
  ) return false;
  return Object.values(value.action.fields).every(
    (field) => isRecord(field) && typeof field.display === "string",
  );
}

function isProvenance(value: unknown): boolean {
  return (
    isRecord(value) &&
    value.mode === "verified-cloud-execution-projection" &&
    value.label === "VERIFIED CLOUD EXECUTION" &&
    strings(value, "description", "basis")
  );
}

function isIdentity(value: unknown): boolean {
  return isRecord(value) && strings(value, "tenant_id", "case_id");
}

function isProposition(value: unknown): boolean {
  return (
    isRecord(value) &&
    strings(value, "predicate", "display") &&
    Array.isArray(value.args) &&
    value.args.every((arg) => typeof arg === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function strings(value: Record<string, unknown>, ...keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === "string");
}
