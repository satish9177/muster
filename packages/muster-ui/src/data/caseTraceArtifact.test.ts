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

  //  ---- the U2 shape: a captured trace that carries an execution ----------

  const executed = (): CaseTraceArtifact => {
    const artifact = structuredClone(artifactSpecimen);
    artifact.result.action.execution = {
      status: "CONFIRMED",
      execution_key: "9f".repeat(32),
      external_reference: "sandbox-pay-9f9f9f9f9f9f9f9f9f9f9f9f",
      outcome_code: "CONFIRMED",
      real_funds: false,
      reserved_at: 1_700_000_000,
      dispatched_at: 1_700_000_001,
      finalized_at: 1_700_000_002,
    };
    return artifact;
  };

  it("renders the durable execution the cloud Action Gate recorded", () => {
    const result = transformCaseTraceArtifact(executed());

    expect(result.action.execution).toBe("CONFIRMED");
    const action = result.events.find((event) => event.kind === "action");
    expect(action?.result).toContain("CONFIRMED");
    expect(action?.result).toContain("NO REAL FUNDS");
    expect(action?.resultTone).toBe("verified");
    expect(action?.inspector.predicates).toContain(
      "external_reference = sandbox-pay-9f9f9f9f9f9f9f9f9f9f9f9f",
    );
    expect(action?.inspector.predicates).toContain("real_funds = false");
  });

  it("shows the persisted lifecycle instants exactly as recorded", () => {
    const result = transformCaseTraceArtifact(executed());
    const action = result.events.find((event) => event.kind === "action");

    expect(action?.inspector.predicates).toContain("state = CONFIRMED");
    expect(action?.inspector.predicates).toContain("reserved_at = 1700000000");
    expect(action?.inspector.predicates).toContain("dispatched_at = 1700000001");
    expect(action?.inspector.predicates).toContain("finalized_at = 1700000002");
  });

  it("labels the state-machine path apart from what the row recorded", () => {
    //  The screen may draw PROPOSED -> RESERVED -> DISPATCHED -> CONFIRMED,
    //  because a confirmed row implies it. What it must not do is present that
    //  drawing as observed data, so the two are separately labelled and only
    //  the instants above are offered as measurements.
    const result = transformCaseTraceArtifact(executed());
    const action = result.events.find((event) => event.kind === "action");

    expect(action?.tags).toContain(
      "STATE MACHINE: PROPOSED → RESERVED → DISPATCHED → CONFIRMED",
    );
    expect(action?.tags).toContain("RECORDED: CONFIRMED");
    expect(action?.inspector.provenanceNote).toContain("not a recorded sequence of events");
  });

  //  A real DISPATCHED row: the executor boundary was crossed and the executor
  //  has not answered, so there is no receipt, no outcome and no finalization.
  //  All three are null, and the viewer has to render that truthfully rather
  //  than demand a value the row cannot have.
  const dispatched = (): CaseTraceArtifact => {
    const artifact = executed();
    artifact.result.action.execution = {
      status: "DISPATCHED",
      execution_key: "9f".repeat(32),
      external_reference: null,
      outcome_code: null,
      real_funds: false,
      reserved_at: 1_700_000_000,
      dispatched_at: 1_700_000_001,
      finalized_at: null,
    };
    return artifact;
  };

  it("renders a dispatched execution whose outcome is not yet known", () => {
    const result = transformCaseTraceArtifact(dispatched());
    const action = result.events.find((event) => event.kind === "action");

    expect(result.action.execution).toBe("DISPATCHED");
    expect(action?.resultTone).toBe("uncertain");
    expect(action?.inspector.predicates).toContain("state = DISPATCHED");
    expect(action?.inspector.predicates).toContain("reserved_at = 1700000000");
    expect(action?.inspector.predicates).toContain("dispatched_at = 1700000001");
    expect(action?.inspector.predicates).toContain("finalized_at = not finalized");
    //  The row has not come back, so the inspector names that and claims
    //  nothing else. See the two tests below for the halves of this.
    expect(action?.inspector.predicates).toContain("finality = OUTCOME_UNKNOWN");
  });

  //  ---- what a dispatched row is not allowed to say -----------------------

  //  The left-hand side of each inspector line, so a test can say "this row
  //  makes no claim of that kind" without also pinning the value it would have
  //  carried.
  const predicateNames = (predicates: readonly string[]): string[] =>
    predicates.map((predicate) => {
      const separator = predicate.indexOf(" = ");
      return separator === -1 ? predicate : predicate.slice(0, separator);
    });

  it("makes no external-reference claim about an execution that has not finalized", () => {
    //  `external_reference = none` is a finding, not a placeholder: it is what
    //  a finalized row reports when there was no receipt to record. A row the
    //  executor has not answered has found nothing, and printing `none` for it
    //  would publish a settled absence in place of an open question.
    const result = transformCaseTraceArtifact(dispatched());
    const action = result.events.find((event) => event.kind === "action");

    expect(predicateNames(action?.inspector.predicates ?? [])).not.toContain(
      "external_reference",
    );
    expect(action?.inspector.predicates.join(" ")).not.toContain("none");
  });

  it("makes no outcome-code claim about an execution that has not finalized", () => {
    const result = transformCaseTraceArtifact(dispatched());
    const action = result.events.find((event) => event.kind === "action");

    expect(predicateNames(action?.inspector.predicates ?? [])).not.toContain("outcome_code");
    expect(action?.inspector.predicates.join(" ")).not.toContain("DISPATCHED = ");
  });

  it("stops the explanatory path at DISPATCHED rather than naming it twice", () => {
    //  `PROPOSED → RESERVED → DISPATCHED → DISPATCHED` draws an edge the Gate
    //  has no transition for, on the one row whose next state is still open.
    const result = transformCaseTraceArtifact(dispatched());
    const action = result.events.find((event) => event.kind === "action");

    expect(action?.tags).toContain("STATE MACHINE: PROPOSED → RESERVED → DISPATCHED");
    expect(action?.tags).toContain("RECORDED: DISPATCHED");
    expect(action?.tags.join(" ")).not.toContain("DISPATCHED → DISPATCHED");
  });

  //  ---- and what a finalized row must still say ---------------------------

  const finalized = (status: "CONFIRMED" | "FAILED" | "UNCERTAIN"): CaseTraceArtifact => {
    const artifact = executed();
    const execution = artifact.result.action.execution as Record<string, unknown>;
    execution.status = status;
    execution.outcome_code = status;
    execution.external_reference = status === "CONFIRMED" ? "sandbox-pay-x" : null;
    return artifact;
  };

  it.each(["CONFIRMED", "FAILED", "UNCERTAIN"] as const)(
    "names %s once at the end of the explanatory path",
    (status) => {
      const result = transformCaseTraceArtifact(finalized(status));
      const action = result.events.find((event) => event.kind === "action");

      expect(action?.tags).toContain(
        `STATE MACHINE: PROPOSED → RESERVED → DISPATCHED → ${status}`,
      );
      expect(action?.tags).toContain(`RECORDED: ${status}`);
    },
  );

  it.each(["CONFIRMED", "FAILED", "UNCERTAIN"] as const)(
    "reports both result fields for %s, because that row has them",
    (status) => {
      //  The distinction this pair of tests exists for: absence is a recorded
      //  answer here and an open question above, so a finalized row keeps the
      //  `external_reference = none` a dispatched row must not print.
      const result = transformCaseTraceArtifact(finalized(status));
      const action = result.events.find((event) => event.kind === "action");
      const predicates = action?.inspector.predicates ?? [];

      expect(predicateNames(predicates)).toContain("external_reference");
      expect(predicates).toContain(`outcome_code = ${status}`);
      expect(predicates).toContain(
        status === "CONFIRMED"
          ? "external_reference = sandbox-pay-x"
          : "external_reference = none",
      );
      expect(predicateNames(predicates)).not.toContain("finality");
    },
  );

  it("refuses an outcome code on an execution that has not finalized", () => {
    const artifact = dispatched();
    const execution = artifact.result.action.execution as Record<string, unknown>;
    execution.outcome_code = "DISPATCHED";

    expect(() => transformCaseTraceArtifact(artifact)).toThrow(/no outcome yet/);
  });

  it.each(["CONFIRMED", "FAILED", "UNCERTAIN"])(
    "still requires an outcome code from %s",
    (status) => {
      const artifact = executed();
      const execution = artifact.result.action.execution as Record<string, unknown>;
      execution.status = status;
      execution.external_reference = status === "CONFIRMED" ? "sandbox-pay-x" : null;
      execution.outcome_code = null;

      expect(() => transformCaseTraceArtifact(artifact)).toThrow(/carries an outcome code/);
    },
  );

  it.each(["reserved_at", "dispatched_at", "finalized_at"])(
    "refuses %s when it is not a durable instant",
    (name) => {
      const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
      const result = unsafe.result as Record<string, unknown>;
      const action = result.action as Record<string, unknown>;
      (action.execution as Record<string, unknown>)[name] = "1700000000";

      expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/durable instant/);
    },
  );

  it("refuses a final execution that carries no finalization instant", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    (action.execution as Record<string, unknown>).finalized_at = null;

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/durable instant/);
  });

  it("refuses a lifecycle whose instants run backwards", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    (action.execution as Record<string, unknown>).dispatched_at = 1_699_999_999;

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/cannot precede/);
  });

  it("refuses a dispatched execution that claims a finalization instant", () => {
    const artifact = dispatched();
    const execution = artifact.result.action.execution as Record<string, unknown>;
    execution.finalized_at = 1_700_000_002;

    expect(() => transformCaseTraceArtifact(artifact)).toThrow(/has not been finalized/);
  });

  it("refuses an artifact claiming the action moved real funds", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    (action.execution as Record<string, unknown>).real_funds = true;

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/real-funds/);
  });

  it.each([0, null, "", "false"])(
    "refuses real_funds spelled as %p rather than exactly false",
    (value) => {
      const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
      const result = unsafe.result as Record<string, unknown>;
      const action = result.action as Record<string, unknown>;
      (action.execution as Record<string, unknown>).real_funds = value;

      expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/real-funds/);
    },
  );

  it("refuses a confirmed execution with no external reference", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    (action.execution as Record<string, unknown>).external_reference = null;

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/external reference/);
  });

  it("refuses an unconfirmed execution that carries a settlement reference", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    const execution = action.execution as Record<string, unknown>;
    execution.status = "UNCERTAIN";

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/no external reference/);
  });

  it("refuses a reservation that never crossed the executor boundary", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    const execution = action.execution as Record<string, unknown>;
    execution.status = "RESERVED";
    execution.external_reference = null;

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/unknown state/);
  });

  it("refuses an unexecuted action that smuggles in an execution key", () => {
    const unsafe = structuredClone(artifactSpecimen) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    action.execution = { status: "NOT_EXECUTED", execution_key: "9f".repeat(32) };

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/no execution fields/);
  });

  it("refuses an execution key that is not a canonical 32-octet digest", () => {
    const unsafe = structuredClone(executed()) as unknown as Record<string, unknown>;
    const result = unsafe.result as Record<string, unknown>;
    const action = result.action as Record<string, unknown>;
    (action.execution as Record<string, unknown>).execution_key = "9F".repeat(32);

    expect(() => transformCaseTraceArtifact(unsafe)).toThrow(/canonical execution key/);
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
