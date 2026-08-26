import { describe, expect, it } from "vitest";

import curatedPayload from "../../public/cases/ravi-milestone-f.json";
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
    mode: "curated-example",
    label: "Curated example",
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
  it("keeps the bundled fallback explicitly distinguishable as curated", () => {
    const result = transformHeroCase(curatedPayload);

    expect(result.provenance.mode).toBe("curated-example");
    expect(result.provenance.capture_available).toBe(false);
  });

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

  //  U2 gave this viewer a second legitimate shape: a captured cloud trace may
  //  now carry the durable Action Gate lifecycle. What has to stay refused is a
  //  state that is not one of the Gate's own -- including RESERVED, which is a
  //  reservation that never crossed the executor boundary rather than something
  //  a screen may render as an outcome.
  it.each(["EXECUTED", "RESERVED", "SETTLED", "", "true"])(
    "rejects a read model naming %s as a durable execution state",
    (state) => {
      const unsafe = structuredClone(specimen) as unknown as Record<string, unknown>;
      const unsafeCase = unsafe.case as Record<string, unknown>;
      const action = unsafeCase.action as Record<string, unknown>;
      action.execution = state;

      expect(() => transformHeroCase(unsafe)).toThrow(/durable execution state/);
    },
  );

  it.each(["NOT_EXECUTED", "DISPATCHED", "CONFIRMED", "FAILED", "UNCERTAIN"])(
    "renders a read model whose action is %s",
    (state) => {
      const accepted = structuredClone(specimen) as unknown as Record<string, unknown>;
      const acceptedCase = accepted.case as Record<string, unknown>;
      const action = acceptedCase.action as Record<string, unknown>;
      action.execution = state;

      expect(transformHeroCase(accepted).action.execution).toBe(state);
    },
  );

  it("rejects duplicate trace identifiers", () => {
    const duplicate = structuredClone(specimen);
    duplicate.events.push(structuredClone(specimen.events[0]!));

    expect(() => transformHeroCase(duplicate)).toThrow(/identifiers must be unique/);
  });

  it("does not allow a curated example to claim an execution capture", () => {
    const misleading = structuredClone(specimen);
    misleading.provenance.capture_available = true;

    expect(() => transformHeroCase(misleading)).toThrow(/cannot claim an execution capture/);
  });
});
