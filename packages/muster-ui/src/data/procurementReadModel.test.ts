import { describe, expect, it } from "vitest";

import fixedPayload from "../../public/cases/procurement-fixed.json";
import perUnitPayload from "../../public/cases/procurement-per-unit.json";
import { transformProcurementCase } from "./procurementReadModel";

describe("transformProcurementCase", () => {
  it("keeps the source disagreement unresolved under both policies", () => {
    const fixed = transformProcurementCase(fixedPayload);
    const perUnit = transformProcurementCase(perUnitPayload);

    expect(fixed.sources.map(({ quantity }) => quantity)).toEqual([100, 97]);
    expect(fixed.sources.map(({ relation }) => relation)).toEqual(["CLAIM", "LOWER_BOUND"]);
    expect(perUnit.sources).toEqual(fixed.sources);
    expect(fixed.uncertainty.status).toBe("UNRESOLVED");
    expect(perUnit.uncertainty.status).toBe("UNRESOLVED");
    expect(fixed.uncertainty.lower_bound).toEqual({
      quantity: 97,
      source_class: "WAREHOUSE_RECEIVING",
      semantics: "CLOSED_LOWER_BOUND",
    });
    expect(fixed.uncertainty.upper_bound).toEqual({
      quantity: 100,
      source_class: "PROCUREMENT_PO",
      semantics: "CLOSED_UPPER_BOUND",
    });
  });

  it("renders kernel-produced alternative actions without calculating them", () => {
    const fixed = transformProcurementCase(fixedPayload);
    const perUnit = transformProcurementCase(perUnitPayload);

    expect(fixed.alternatives.map(({ amount }) => amount)).toEqual([
      "₹63,000",
      "₹63,000",
      "₹63,000",
      "₹63,000",
    ]);
    expect(perUnit.alternatives.map(({ amount }) => amount)).toEqual([
      "₹61,110",
      "₹61,740",
      "₹62,370",
      "₹63,000",
    ]);
    expect(fixed.result.outcome).toBe("INVARIANT");
    expect(perUnit.result.outcome).toBe("DIVERGENT");
  });

  it("fails closed when the evidence plan is malformed", () => {
    const malformed = structuredClone(perUnitPayload) as unknown as Record<string, unknown>;
    const result = malformed.result as Record<string, unknown>;
    result.additional_evidence = null;

    expect(() => transformProcurementCase(malformed)).toThrow(/malformed/);
  });

  it("rejects a claimed invariant whose returned actions differ", () => {
    const contradictory = structuredClone(fixedPayload);
    contradictory.alternatives[0]!.action.amount_minor = 6111000;

    expect(() => transformProcurementCase(contradictory)).toThrow(/inconsistent/);
  });
});
