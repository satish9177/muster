export type ProcurementPolicyKey = "FIXED_TOLERANCE" | "PER_UNIT";
export type ProcurementOutcome = "INVARIANT" | "DIVERGENT";

interface RawAction {
  kind: "PAY";
  recipient: string;
  currency: "INR";
  amount_minor: number;
}

interface RawSource {
  label: string;
  source_class: string;
  quantity: number;
  relation: "CLAIM" | "LOWER_BOUND";
}

interface RawQuantityBound {
  quantity: number;
  source_class: string;
  semantics: "CLOSED_LOWER_BOUND" | "CLOSED_UPPER_BOUND";
}

interface RawHinge {
  predicate: string;
  label: string;
  permitted_source_classes: string[];
}

export interface RawProcurementCase {
  schema_version: "muster.procurement-case/v1";
  case: {
    tenant_id: string;
    case_id: string;
    po_id: string;
    supplier: string;
    title: string;
  };
  sources: RawSource[];
  uncertainty: {
    predicate: string;
    status: "UNRESOLVED";
    admissible_min: number;
    admissible_max: number;
    lower_bound: RawQuantityBound;
    upper_bound: RawQuantityBound;
  };
  policy: {
    key: ProcurementPolicyKey;
    policy_id: string;
    version: string;
    manifest_digest: string;
    acceptance_minimum: number;
    fixed_amount_minor: number;
    per_unit_rate_minor: number;
    currency: "INR";
  };
  alternatives: Array<{ quantity: number; action: RawAction }>;
  result: {
    outcome: ProcurementOutcome;
    proposed_action: RawAction | null;
    additional_evidence: {
      status: "NONE_REQUIRED" | "REQUIRED";
      reason: string;
      hinge: RawHinge | null;
    };
    reachable_action_count: number;
  };
  provenance: {
    mode: "deterministic-local-replay";
    description: string;
    basis: string;
  };
}

export interface ProcurementCaseViewModel {
  case: RawProcurementCase["case"];
  sources: RawSource[];
  uncertainty: RawProcurementCase["uncertainty"];
  policy: RawProcurementCase["policy"] & {
    fixedAmount: string;
    perUnitRate: string;
  };
  alternatives: Array<{ quantity: number; amount: string }>;
  result: RawProcurementCase["result"] & {
    proposedAmount: string | null;
  };
  provenance: RawProcurementCase["provenance"];
}

export function transformProcurementCase(input: unknown): ProcurementCaseViewModel {
  assertProcurementCase(input);
  const formatMoney = (minor: number) =>
    new Intl.NumberFormat("en-IN", {
      style: "currency",
      currency: input.policy.currency,
      maximumFractionDigits: 0,
    }).format(minor / 100);

  return {
    case: { ...input.case },
    sources: input.sources.map((source) => ({ ...source })),
    uncertainty: { ...input.uncertainty },
    policy: {
      ...input.policy,
      fixedAmount: formatMoney(input.policy.fixed_amount_minor),
      perUnitRate: formatMoney(input.policy.per_unit_rate_minor),
    },
    alternatives: input.alternatives.map(({ quantity, action }) => ({
      quantity,
      amount: formatMoney(action.amount_minor),
    })),
    result: {
      ...input.result,
      proposedAmount:
        input.result.proposed_action === null
          ? null
          : formatMoney(input.result.proposed_action.amount_minor),
    },
    provenance: { ...input.provenance },
  };
}

function assertProcurementCase(input: unknown): asserts input is RawProcurementCase {
  if (!isRecord(input) || input.schema_version !== "muster.procurement-case/v1") {
    throw new Error("Unsupported MUSTER procurement read model");
  }
  const uncertainty = input.uncertainty;
  if (
    !isCase(input.case) ||
    !Array.isArray(input.sources) ||
    input.sources.length !== 2 ||
    !input.sources.every(isSource) ||
    !isUncertainty(uncertainty) ||
    !isPolicy(input.policy) ||
    !Array.isArray(input.alternatives) ||
    input.alternatives.length !== 4 ||
    !input.alternatives.every(isAlternative) ||
    !isResult(input.result) ||
    !isProvenance(input.provenance)
  ) {
    throw new Error("Procurement read model is malformed");
  }
  if (input.sources[0]!.quantity === input.sources[1]!.quantity) {
    throw new Error("Procurement source disagreement was silently reconciled");
  }
  const expectedQuantities = Array.from(
    { length: uncertainty.admissible_max - uncertainty.admissible_min + 1 },
    (_, index) => uncertainty.admissible_min + index,
  );
  if (
    input.alternatives.length !== expectedQuantities.length ||
    !input.alternatives.every(({ quantity }, index) => quantity === expectedQuantities[index])
  ) {
    throw new Error("Procurement alternatives must cover the admissible quantity interval");
  }
  if (!resultShapeMatchesOutcome(input.result, input.alternatives)) {
    throw new Error("Procurement outcome and evidence plan are inconsistent");
  }
}

function resultShapeMatchesOutcome(
  result: RawProcurementCase["result"],
  alternatives: RawProcurementCase["alternatives"],
): boolean {
  if (result.outcome === "INVARIANT") {
    return (
      result.proposed_action !== null &&
      result.additional_evidence.status === "NONE_REQUIRED" &&
      result.additional_evidence.hinge === null &&
      alternatives.every(
        ({ action }) => action.amount_minor === result.proposed_action?.amount_minor,
      )
    );
  }
  return (
    result.proposed_action === null &&
    result.additional_evidence.status === "REQUIRED" &&
    result.additional_evidence.hinge !== null &&
    alternatives[0]!.action.amount_minor !== alternatives[1]!.action.amount_minor
  );
}

function isCase(value: unknown): value is RawProcurementCase["case"] {
  return (
    isRecord(value) &&
    allStrings(value, "tenant_id", "case_id", "po_id", "supplier", "title")
  );
}

function isSource(value: unknown): value is RawSource {
  return (
    isRecord(value) &&
    allStrings(value, "label", "source_class") &&
    Number.isInteger(value.quantity) &&
    (value.relation === "CLAIM" || value.relation === "LOWER_BOUND")
  );
}

function isUncertainty(value: unknown): value is RawProcurementCase["uncertainty"] {
  return (
    isRecord(value) &&
    typeof value.predicate === "string" &&
    value.status === "UNRESOLVED" &&
    Number.isInteger(value.admissible_min) &&
    Number.isInteger(value.admissible_max) &&
    Number(value.admissible_min) <= Number(value.admissible_max) &&
    isQuantityBound(value.lower_bound, "CLOSED_LOWER_BOUND") &&
    isQuantityBound(value.upper_bound, "CLOSED_UPPER_BOUND") &&
    value.lower_bound.quantity === value.admissible_min &&
    value.upper_bound.quantity === value.admissible_max
  );
}

function isQuantityBound(
  value: unknown,
  semantics: RawQuantityBound["semantics"],
): value is RawQuantityBound {
  return (
    isRecord(value) &&
    Number.isInteger(value.quantity) &&
    typeof value.source_class === "string" &&
    value.semantics === semantics
  );
}

function isPolicy(value: unknown): value is RawProcurementCase["policy"] {
  return (
    isRecord(value) &&
    (value.key === "FIXED_TOLERANCE" || value.key === "PER_UNIT") &&
    allStrings(value, "policy_id", "version", "manifest_digest") &&
    typeof value.manifest_digest === "string" &&
    /^[0-9a-f]{64}$/.test(value.manifest_digest) &&
    value.currency === "INR" &&
    allIntegers(value, "acceptance_minimum", "fixed_amount_minor", "per_unit_rate_minor")
  );
}

function isAction(value: unknown): value is RawAction {
  return (
    isRecord(value) &&
    value.kind === "PAY" &&
    typeof value.recipient === "string" &&
    value.currency === "INR" &&
    Number.isInteger(value.amount_minor)
  );
}

function isAlternative(value: unknown): value is RawProcurementCase["alternatives"][number] {
  return isRecord(value) && Number.isInteger(value.quantity) && isAction(value.action);
}

function isResult(value: unknown): value is RawProcurementCase["result"] {
  if (
    !isRecord(value) ||
    (value.outcome !== "INVARIANT" && value.outcome !== "DIVERGENT") ||
    (value.proposed_action !== null && !isAction(value.proposed_action)) ||
    !Number.isInteger(value.reachable_action_count) ||
    !isRecord(value.additional_evidence)
  ) {
    return false;
  }
  const evidence = value.additional_evidence;
  return (
    (evidence.status === "NONE_REQUIRED" || evidence.status === "REQUIRED") &&
    typeof evidence.reason === "string" &&
    (evidence.hinge === null || isHinge(evidence.hinge))
  );
}

function isHinge(value: unknown): value is RawHinge {
  return (
    isRecord(value) &&
    allStrings(value, "predicate", "label") &&
    Array.isArray(value.permitted_source_classes) &&
    value.permitted_source_classes.length > 0 &&
    value.permitted_source_classes.every((item) => typeof item === "string")
  );
}

function isProvenance(value: unknown): value is RawProcurementCase["provenance"] {
  return (
    isRecord(value) &&
    value.mode === "deterministic-local-replay" &&
    allStrings(value, "description", "basis")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function allStrings(value: Record<string, unknown>, ...keys: string[]): boolean {
  return keys.every((key) => typeof value[key] === "string");
}

function allIntegers(value: Record<string, unknown>, ...keys: string[]): boolean {
  return keys.every((key) => Number.isInteger(value[key]));
}
