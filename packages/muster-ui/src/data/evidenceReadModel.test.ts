import { describe, expect, it } from "vitest";

import tracePayload from "../../public/cases/ravi-cloud-execution.json";
import proofPayload from "../../public/cases/ravi-evidence-proof.json";
import evidenceComponentSource from "../components/RaviEvidence.tsx?raw";
import type { CaseTraceArtifact } from "./caseTraceArtifact";
import { transformRaviEvidence } from "./evidenceReadModel";

const artifactSpecimen = tracePayload as unknown as CaseTraceArtifact;

describe("transformRaviEvidence", () => {
  it("joins committed input modality with captured candidate facts and cloud metadata", () => {
    const result = transformRaviEvidence(artifactSpecimen, proofPayload);

    expect(result.worker.modalities).toEqual(["TEXT"]);
    expect(result.worker.captureStatus).toContain("NOT RERUN IN CLOUD CAPTURE");
    expect(result.worker.candidateFacts).toEqual(["present_on_site(RAVI,SAT) = true"]);
    expect(result.employer.candidateFacts).toEqual(["scheduled(RAVI,SAT) = true"]);
    expect(result.site.modalities).toEqual(["IMAGE", "TEXT"]);
    expect(result.site.sourceMaterial).toContainEqual(
      expect.objectContaining({ file: "attendance-board-sat.png", mediaType: "image/png" }),
    );
    expect(result.site.candidateFacts).toEqual([
      "present_on_site(RAVI,SAT) = true",
      "on_site_duration(RAVI,SAT) ≥ 508",
    ]);
    expect(result.execution).toEqual(
      expect.objectContaining({
        name: "muster-control-plane-hero-htkpt",
        modelName: "gemini-3.7-flash",
        modelLocation: "global",
        cloudRunRegion: "asia-south1",
      }),
    );
  });

  it("labels execution replay separately from implementation-audit metadata", () => {
    expect(evidenceComponentSource).toContain(
      "VERIFIED CLOUD EXECUTION REPLAY · ravi-cloud-execution.json",
    );
    expect(evidenceComponentSource).toContain(
      "IMPLEMENTATION AUDIT · ravi-evidence-proof.json",
    );
    expect(evidenceComponentSource).toContain("not runtime telemetry");
    expect(evidenceComponentSource).toContain("WORKER NOT RERUN");
  });

  it("takes IAM status, model identity, and candidate facts from the execution artifact", () => {
    const changed = structuredClone(artifactSpecimen);
    changed.provenance.source = "deterministic-local-replay";
    changed.provenance.captured = false;
    changed.security_boundary.http_status = 401;
    changed.execution.model = { name: "different-model", location: "different-location" };
    changed.attestations[1]!.relation = {
      kind: "EXACT",
      value: { type: "bool", value: false },
    };

    const result = transformRaviEvidence(changed, proofPayload);
    expect(result.boundary.httpStatus).toBe(401);
    expect(result.execution.modelName).toBe("different-model");
    expect(result.execution.modelLocation).toBe("different-location");
    expect(result.site.candidateFacts[0]).toBe("present_on_site(RAVI,SAT) = false");
  });

  it("fails closed when the path audit does not prove the inline image delivery", () => {
    const malformed = structuredClone(proofPayload);
    malformed.site.source_material[0]!.delivery = "UNKNOWN";
    expect(() => transformRaviEvidence(artifactSpecimen, malformed)).toThrow(/image path/);
  });
});
