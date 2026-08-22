import { describe, expect, it } from "vitest";

import {
  CASE_TRACE_SCHEMA_VERSION,
  transformCaseTraceArtifact,
  type CaseTraceArtifact,
} from "./caseTraceArtifact";

export const artifactSpecimen: CaseTraceArtifact = {
  schema_version: CASE_TRACE_SCHEMA_VERSION,
  case_id: "CASE-RAVI-SAT-CLOUD",
  tenant_id: "TENANT-1",
  provenance: { source: "verified-cloud-execution", captured: true },
  execution: {
    project_id: "muster-project",
    job_name: "muster-control-plane-hero",
    execution_name: "muster-control-plane-hero-abcde",
    executed_at: "2026-08-22T10:00:00Z",
    completed_at: "2026-08-22T10:01:00Z",
    cloud_run_region: "asia-south1",
    model: { name: "gemini-3.7-flash", location: "global" },
  },
  policy: { policy_id: "workforce-v1", bundle_digest: "ab".repeat(32) },
  claim: {
    claimant: "RAVI",
    role: "WORKER",
    proposition: { predicate: "present_on_site", args: ["RAVI", "SAT"] },
    asserted_value: { type: "bool", value: true },
    authority: "CLAIM_ONLY",
  },
  plan: {
    request_id: "cd".repeat(32),
    requirements: [
      {
        proposition: { predicate: "scheduled", args: ["RAVI", "SAT"] },
        permitted_source_classes: ["HR_PAYROLL_SYSTEM"],
      },
      {
        proposition: { predicate: "present_on_site", args: ["RAVI", "SAT"] },
        permitted_source_classes: ["SITE_ACCESS_CONTROL"],
      },
      {
        proposition: { predicate: "on_site_duration", args: ["RAVI", "SAT"] },
        permitted_source_classes: ["SITE_ACCESS_CONTROL"],
      },
    ],
  },
  security_boundary: {
    actor: "muster-control-plane",
    operation: "storage.objects.get",
    target_class: "site-evidence",
    result: "DENIED",
    http_status: 403,
    enforcement: "GCP IAM",
  },
  attestations: [
    {
      agent_id: "agent-hr-payroll",
      source_class: "HR_PAYROLL_SYSTEM",
      source_id: "EMPLOYER-1",
      proposition: { predicate: "scheduled", args: ["RAVI", "SAT"] },
      relation: { kind: "EXACT", value: { type: "bool", value: true } },
      signer_key_ref: "key-hr-payroll-cloud-1",
      entry_digest: "ef".repeat(32),
      authorization: { check: "Q-12", status: "PASSED" },
      disclosure_class: "RECORD",
      model_interpretation: true,
    },
    {
      agent_id: "agent-site-a",
      source_class: "SITE_ACCESS_CONTROL",
      source_id: "SITE-A",
      proposition: { predicate: "present_on_site", args: ["RAVI", "SAT"] },
      relation: { kind: "EXACT", value: { type: "bool", value: true } },
      signer_key_ref: "key-site-a-cloud-1",
      entry_digest: "01".repeat(32),
      authorization: { check: "Q-12", status: "PASSED" },
      disclosure_class: "OBSERVATION",
      model_interpretation: true,
    },
    {
      agent_id: "agent-site-a",
      source_class: "SITE_ACCESS_CONTROL",
      source_id: "SITE-A",
      proposition: { predicate: "on_site_duration", args: ["RAVI", "SAT"] },
      relation: { kind: "CLOSED_LOWER_BOUND", value: { type: "int", value: 240 } },
      signer_key_ref: "key-site-a-cloud-1",
      entry_digest: "23".repeat(32),
      authorization: { check: "Q-12", status: "PASSED" },
      disclosure_class: "OBSERVATION",
      model_interpretation: true,
    },
  ],
  result: {
    status: "PROPOSED",
    outcome: "INVARIANT",
    rebuild: { processor: "REPRODUCIBLE", certificate_reproduced: true },
    action: {
      kind: "PAY",
      fields: [
        { name: "recipient", value: { type: "enum", enum_id: "party", value: "RAVI" } },
        { name: "amount", value: { type: "scaled", unit: "INR", scale: 2, minor: 510000 } },
      ],
      execution: { status: "NOT_EXECUTED" },
    },
    unresolved: [
      { predicate: "on_site_duration", args: ["RAVI", "SAT"] },
      { predicate: "shift_payable_under_policy", args: ["RAVI", "SAT"] },
    ],
  },
};

describe("transformCaseTraceArtifact", () => {
  it("preserves cloud provenance, Q-12, the invariant proposal, and unresolved duration", () => {
    const result = transformCaseTraceArtifact(artifactSpecimen);

    expect(result.provenance.label).toBe("VERIFIED CLOUD EXECUTION REPLAY");
    expect(result.provenance.mode).toBe("verified-cloud-execution");
    expect(result.action.amount).toBe("₹5,100");
    expect(result.action.execution).toBe("NOT_EXECUTED");
    expect(result.unresolved).toEqual([
      "on_site_duration(RAVI, SAT)",
      "shift_payable_under_policy(RAVI, SAT)",
    ]);
    expect(result.events).toHaveLength(7);
    expect(result.events.filter((event) => event.kind === "agent").every(
      (event) => event.inspector.q12Result.includes("PASSED"),
    )).toBe(true);
  });

  it("sources the boundary status from artifact data", () => {
    const changed = structuredClone(artifactSpecimen);
    changed.provenance.source = "deterministic-local-replay";
    changed.provenance.captured = false;
    changed.execution.execution_name = null;
    changed.execution.executed_at = null;
    changed.execution.completed_at = null;
    changed.security_boundary.http_status = 401;

    const boundary = transformCaseTraceArtifact(changed).events.find((event) => event.kind === "boundary");
    expect(boundary?.httpStatus).toBe(401);
    expect(boundary?.result).toContain("HTTP 401");
  });

  it("fails closed on an unknown schema or missing mandatory field", () => {
    const unknown = structuredClone(artifactSpecimen) as unknown as Record<string, unknown>;
    unknown.schema_version = "muster.case-trace/v2";
    expect(() => transformCaseTraceArtifact(unknown)).toThrow(/Unsupported/);

    const incomplete = structuredClone(artifactSpecimen) as unknown as Record<string, unknown>;
    delete incomplete.plan;
    expect(() => transformCaseTraceArtifact(incomplete)).toThrow(/plan/);
  });

  it("refuses an uncaptured artifact that claims verified cloud provenance", () => {
    const uncaptured = structuredClone(artifactSpecimen);
    uncaptured.provenance.captured = false;
    expect(() => transformCaseTraceArtifact(uncaptured)).toThrow(/not bound/);
  });
});
