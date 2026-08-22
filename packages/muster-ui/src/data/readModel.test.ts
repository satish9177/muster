import { describe, expect, it } from "vitest";

import { transformHeroCase, type RawHeroCase } from "./readModel";

const specimen: RawHeroCase = {
  schema_version: "muster.hero-case/v1",
  case: {
    id: "case-ravi-saturday",
    title: "Ravi — Saturday Shift Pay",
    subject: "RAVI",
    pinned_policy: "scheduled ∧ present_on_site ∧ duration ≥ 240m ⇒ PAY daily_rate",
    policy_version: "Q-12 / workforce-v1",
    status: "PROPOSED",
    outcome: "INVARIANT",
    action: {
      kind: "PAY",
      recipient: "RAVI",
      currency: "INR",
      amount_minor: 510000,
      execution: "NOT_EXECUTED",
    },
    unresolved: ["exact on-site duration"],
  },
  provenance: {
    mode: "verified-replay",
    label: "Verified replay",
    description: "Not live telemetry",
    basis: "Milestone F",
    captured_at: null,
    capture_available: false,
  },
  events: [
    {
      id: "claim",
      sequence: "01",
      kind: "claim",
      actor: "Worker Agent",
      eyebrow: "Worker claim",
      title: "I worked Saturday.",
      summary: "A claim has no authority.",
      result: "CLAIM ONLY — INERT",
      result_tone: "neutral",
      tags: [],
      inspector: {
        source_class: "CLAIM",
        source_identity: "RAVI",
        key_id: null,
        authority_grant: "None",
        predicates: ["present_on_site(RAVI,SAT) [claimed]"],
        disclosure: "Claim only",
        q12_result: "Not applicable",
        model_interpretation: "No",
        deterministic_decision: "No",
        provenance_note: "Test specimen",
      },
    },
  ],
};

describe("transformHeroCase", () => {
  it("formats the decided amount while preserving unresolved facts", () => {
    const result = transformHeroCase(specimen);

    expect(result.action.amount).toBe("₹5,100");
    expect(result.action.execution).toBe("NOT_EXECUTED");
    expect(result.unresolved).toEqual(["exact on-site duration"]);
  });

  it("maps source provenance without creating policy decisions", () => {
    const result = transformHeroCase(specimen);

    expect(result.events[0]?.inspector.sourceIdentity).toBe("RAVI");
    expect(result.events[0]?.result).toBe("CLAIM ONLY — INERT");
  });

  it("rejects any read model that claims UI-1 executed an action", () => {
    const unsafe = structuredClone(specimen) as unknown as Record<string, unknown>;
    const unsafeCase = unsafe.case as Record<string, unknown>;
    const action = unsafeCase.action as Record<string, unknown>;
    action.execution = "EXECUTED";

    expect(() => transformHeroCase(unsafe)).toThrow(/not been executed/);
  });

  it("rejects duplicate trace identifiers", () => {
    const duplicate = structuredClone(specimen);
    duplicate.events.push(structuredClone(specimen.events[0]!));

    expect(() => transformHeroCase(duplicate)).toThrow(/identifiers must be unique/);
  });

  it("does not allow an un-timestamped model to present itself as live", () => {
    const misleading = structuredClone(specimen);
    misleading.provenance.mode = "live";

    expect(() => transformHeroCase(misleading)).toThrow(/observation timestamp/);
  });
});
