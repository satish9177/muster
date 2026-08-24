import { describe, expect, it } from "vitest";

import payload from "../../public/cases/ravi-evidence-plan.json";
import componentSource from "../components/EvidencePlanner.tsx?raw";
import { parseEvidencePlan } from "./evidencePlanReadModel";

describe("parseEvidencePlan", () => {
  it("renders the generated plan, lower bound, stop reason, and final action", () => {
    const model = parseEvidencePlan(payload);
    expect(model.required_resolved.map((item) => item.proposition.predicate)).toEqual([
      "scheduled",
      "present_on_site",
      "on_site_duration",
    ]);
    expect(model.required_resolved[2]?.label).toBe("On-site duration — threshold only");
    expect(model.required_resolved[2]?.requirement).toContain("240");
    expect(model.required_resolved[2]?.established).toContain("508");
    expect(model.not_required[0]?.label).toBe("Exact minute count — never established");
    expect(model.not_required[0]?.unresolved).toBe(true);
    expect(model.summary).toMatchObject({
      reachable_action_count: 1,
      outcome: "INVARIANT",
      exact_duration_status: "UNRESOLVED",
    });
    expect(model.summary.action.fields.amount?.display).toBe("INR 5,100.00");
    expect(model.provenance.label).toBe("VERIFIED CLOUD EXECUTION");
  });

  it("keeps policy values and proposition names out of React reasoning", () => {
    expect(componentSource).not.toMatch(/\b(?:240|508|510000)\b/);
    expect(componentSource).not.toContain("on_site_duration");
    expect(componentSource).not.toContain("scheduled(RAVI");
    expect(componentSource).not.toMatch(/reachable_action_count\s*[+*/-]/);
  });

  it("rejects malformed provenance and stop-state claims", () => {
    const malformed = structuredClone(payload) as unknown as Record<string, unknown>;
    (malformed.provenance as Record<string, unknown>).label = "CLOUD SQL";
    expect(() => parseEvidencePlan(malformed)).toThrow(/malformed/);

    const resolved = structuredClone(payload) as unknown as Record<string, unknown>;
    ((resolved.not_required as Array<Record<string, unknown>>)[0]!).unresolved = false;
    expect(() => parseEvidencePlan(resolved)).toThrow(/malformed/);
  });
});
