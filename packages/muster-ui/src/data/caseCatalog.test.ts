import { describe, expect, it } from "vitest";

import fixedPayload from "../../public/cases/procurement-fixed.json";
import tracePayload from "../../public/cases/ravi-cloud-execution.json";
import { buildCaseCatalog } from "./caseCatalog";
import { transformCaseTraceArtifact, type CaseTraceArtifact } from "./caseTraceArtifact";
import { transformProcurementCase } from "./procurementReadModel";

const artifactSpecimen = tracePayload as unknown as CaseTraceArtifact;

describe("buildCaseCatalog", () => {
  it("projects existing read-model results without calculating either case", () => {
    const workforce = transformCaseTraceArtifact(artifactSpecimen);
    const procurement = transformProcurementCase(fixedPayload);
    const catalog = buildCaseCatalog(workforce, procurement);

    expect(catalog.workforce.outcome).toBe(workforce.outcome);
    expect(catalog.workforce.actionAmount).toBe(workforce.action.amount);
    expect(catalog.procurement.outcome).toBe(procurement.result.outcome);
    expect(catalog.procurement.title).toContain(procurement.case.po_id);
  });

  it("does not contain a second result rule in the case selector path", () => {
    const workforce = transformCaseTraceArtifact(artifactSpecimen);
    const procurement = transformProcurementCase(fixedPayload);
    const changedWorkforce = { ...workforce, outcome: "DIVERGENT" as unknown as "INVARIANT" };
    const changedProcurement = {
      ...procurement,
      result: { ...procurement.result, outcome: "DIVERGENT" as const },
    };

    const catalog = buildCaseCatalog(changedWorkforce, changedProcurement);
    expect(catalog.workforce.outcome).toBe("DIVERGENT");
    expect(catalog.procurement.outcome).toBe("DIVERGENT");
  });
});
