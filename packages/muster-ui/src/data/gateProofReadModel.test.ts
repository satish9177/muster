import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import proofPayload from "../../public/cases/ravi-cloud-gate-proof.json";
import analysisOnlyPayload from "../../public/cases/ravi-cloud-execution.json";
import { CloudGateProof } from "../components/CloudGateProof";
import proofPanelSource from "../components/CloudGateProof.tsx?raw";
import { HttpGateProofClient } from "./gateProofClient";
import {
  GATE_PROOF_SCHEMA_VERSION,
  isControlPlaneStage,
  proofSummary,
  transformGateProof,
} from "./gateProofReadModel";

const DEPLOYED_SOURCE_COMMIT = "af1359c828d70e9e860f10ae076f225b006e5693";
const DOCUMENTATION_COMMIT = "f03f6207f4911c33ec7342bcfb2b88471ef1c1b8";
const EXECUTION_ID = "6e9de1415fb0056e7c2e41b4b3d1d15008a980e0b19a7afde70c86f0642d5b80";
const IMAGE_DIGEST =
  "sha256:77e0060833b982b471b7b7e272ee37eb438e3e551e79ba004cb41e94ca2e9d73";

/** A deep copy, so a mutation in one case cannot leak into the next. */
function specimen(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(proofPayload)) as Record<string, unknown>;
}

function stage(document: Record<string, unknown>, index: number): Record<string, unknown> {
  return (document.stages as Record<string, unknown>[])[index]!;
}

describe("the tracked final Gate proof", () => {
  it("is the af1359c proof, not the later documentation head", () => {
    const model = transformGateProof(proofPayload);

    expect(model.schemaVersion).toBe(GATE_PROOF_SCHEMA_VERSION);
    expect(model.provenance.deployedSourceCommit).toBe(DEPLOYED_SOURCE_COMMIT);
    expect(model.provenance.documentationCommit).toBe(DOCUMENTATION_COMMIT);
    expect(model.provenance.executionId).toBe(EXECUTION_ID);
    expect(model.provenance.imageDigest).toBe(IMAGE_DIGEST);
    expect(model.provenance.controlPlaneImage).toContain(`@${IMAGE_DIGEST}`);
    expect(model.provenance.caseId).toBe("CASE-RAVI-SAT-CLOUD-GATE-FINAL-B-AF1359C");
    expect(model.provenance.tenantId).toBe("BETA");
    expect(model.externalReference).toBe(`sandbox-pay-${EXECUTION_ID}`);
  });

  it("names the five Cloud Run executions in the observed order", () => {
    const model = transformGateProof(proofPayload);
    expect(model.stages.map((entry) => [entry.id, entry.cloudRunExecution])).toEqual([
      ["unknown_after_acceptance", "muster-control-plane-hero-z2m6k"],
      ["pre_reconciliation_external_read", "muster-database-bootstrap-jkr7k"],
      ["reconciliation", "muster-control-plane-hero-hdfv2"],
      ["exact_idempotency_read", "muster-control-plane-hero-pv2f2"],
      ["final_external_read", "muster-database-bootstrap-kpz8p"],
    ]);
  });

  it("records one dispatch, zero redispatch, and one surviving transfer", () => {
    const summary = proofSummary(transformGateProof(proofPayload));
    expect(summary).toEqual({
      externalEffects: 1,
      redispatches: 0,
      finalTransferCount: 1,
    });
  });

  it("carries the uncertainty and the reconciliation exactly as observed", () => {
    const model = transformGateProof(proofPayload);
    const [unknown, , reconciled, idempotent] = model.stages as [
      (typeof model.stages)[number],
      (typeof model.stages)[number],
      (typeof model.stages)[number],
      (typeof model.stages)[number],
      (typeof model.stages)[number],
    ];

    expect(isControlPlaneStage(unknown) && unknown.state).toBe("UNCERTAIN");
    expect(isControlPlaneStage(unknown) && unknown.outcomeCode).toBe("EXECUTOR_EXCEPTION");
    expect(isControlPlaneStage(unknown) && unknown.externalReference).toBe(null);
    expect(isControlPlaneStage(unknown) && unknown.dispatches).toBe(1);

    expect(isControlPlaneStage(reconciled) && reconciled.state).toBe("CONFIRMED");
    expect(isControlPlaneStage(reconciled) && reconciled.finality).toBe("DEFINITELY_EXECUTED");
    expect(isControlPlaneStage(reconciled) && reconciled.reconciledFrom).toBe("UNCERTAIN");
    expect(isControlPlaneStage(reconciled) && reconciled.dispatches).toBe(0);
    expect(isControlPlaneStage(reconciled) && reconciled.inspections).toBe(1);

    //  The idempotency read reported a state and two counters and nothing
    //  else. Carrying the previous stage's finality into it would put an
    //  unobserved fact on the screen.
    expect(isControlPlaneStage(idempotent) && idempotent.finality).toBe(null);
    expect(isControlPlaneStage(idempotent) && idempotent.dispatches).toBe(0);
    expect(isControlPlaneStage(idempotent) && idempotent.inspections).toBe(0);
  });

  it("asserts the four safety claims", () => {
    const model = transformGateProof(proofPayload);
    expect(model.claims).toEqual({
      sandboxOnly: true,
      realFunds: false,
      liveTelemetry: false,
      cloudRunProcessDeathClaimed: false,
    });
  });

  it("is a different document from the analysis-only Stage-90 trace", () => {
    expect((analysisOnlyPayload as { schema_version: string }).schema_version).toBe(
      "muster.case-trace/v1",
    );
    //  The historical artifact still says NOT_EXECUTED, and it must keep
    //  saying so: it is a different run, and reinterpreting it here would be
    //  rewriting evidence rather than adding some.
    expect(() => transformGateProof(analysisOnlyPayload)).toThrow(
      /Unsupported Action Gate proof record/,
    );
  });
});

describe("transformGateProof fails closed", () => {
  it("refuses a record that drops any of the four safety claims", () => {
    for (const claim of [
      "sandbox_only",
      "real_funds",
      "live_telemetry",
      "cloud_run_process_death_claimed",
    ]) {
      const document = specimen();
      (document.claims as Record<string, unknown>)[claim] = claim === "sandbox_only"
        ? false
        : true;
      expect(() => transformGateProof(document)).toThrow(/sandbox replay claims/);
    }
  });

  it("refuses a record that collapses the deployed and documentation commits", () => {
    const document = specimen();
    (document.provenance as Record<string, unknown>).deployed_source_commit =
      DOCUMENTATION_COMMIT;
    expect(() => transformGateProof(document)).toThrow(/must stay distinct/);
  });

  it("refuses an image that does not carry its own digest", () => {
    const document = specimen();
    (document.provenance as Record<string, unknown>).control_plane_image =
      "asia-south1-docker.pkg.dev/muster-agentic-2026-9177/muster/muster-control-plane:latest";
    expect(() => transformGateProof(document)).toThrow(/does not carry its own digest/);
  });

  it("refuses a redispatch after the answer was lost", () => {
    const document = specimen();
    //  The total stays at one, so only the "no dispatch after stage one" rule
    //  can catch this. A record that moved the dispatch to the reconciliation
    //  would be describing a retry, which is the thing MUSTER does not do.
    stage(document, 0).dispatches = 0;
    stage(document, 2).dispatches = 1;
    expect(() => transformGateProof(document)).toThrow(/redispatches/);
  });

  it("refuses more than one dispatch in total", () => {
    const document = specimen();
    stage(document, 0).dispatches = 2;
    expect(() => transformGateProof(document)).toThrow(/not exactly one/);
  });

  it("refuses a second external effect", () => {
    const document = specimen();
    stage(document, 4).transfer_count = 2;
    expect(() => transformGateProof(document)).toThrow(/exactly one external transfer/);
  });

  it("refuses an external-world read that claims to have written", () => {
    const document = specimen();
    stage(document, 1).read_only = false;
    expect(() => transformGateProof(document)).toThrow(/not read-only/);
  });

  it("refuses a settlement reference on an uncertain row", () => {
    const document = specimen();
    stage(document, 0).external_reference = `sandbox-pay-${EXECUTION_ID}`;
    expect(() => transformGateProof(document)).toThrow(/reference while uncertain/);
  });

  it("refuses half a reconciliation provenance pair", () => {
    const document = specimen();
    stage(document, 2).reconciled_at = null;
    expect(() => transformGateProof(document)).toThrow(/partial reconciliation provenance/);
  });

  it("refuses an external reference that disagrees with the proof", () => {
    const document = specimen();
    stage(document, 1).external_reference = "sandbox-pay-somewhere-else";
    expect(() => transformGateProof(document)).toThrow(/malformed or not read-only/);
  });
});

describe("HttpGateProofClient", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads the tracked artifact with GET and nothing else", async () => {
    const fetchMock = vi.fn(
      async (_url: string, _init: RequestInit) =>
        new Response(JSON.stringify(proofPayload), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const model = await new HttpGateProofClient().load();

    expect(model.provenance.deployedSourceCommit).toBe(DEPLOYED_SOURCE_COMMIT);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/cases/ravi-cloud-gate-proof.json");
    expect(init.method).toBe("GET");
  });

  it("reports an unavailable artifact rather than inventing a result", async () => {
    vi.stubGlobal("fetch", async () => new Response("", { status: 404 }));
    await expect(new HttpGateProofClient().load()).rejects.toThrow(/unavailable \(404\)/);
  });
});

describe("the judge-facing proof panel", () => {
  it("renders without a backend and without a control", () => {
    const markup = renderToStaticMarkup(createElement(CloudGateProof));
    //  The first paint happens before any fetch resolves, and it must already
    //  be honest and inert: no form, no button, nothing to press.
    expect(markup).toContain("Loading the verified Google Cloud replay");
    expect(markup).not.toContain("<button");
    expect(markup).not.toContain("<form");
  });

  it("carries no wording a judge could read as live, real, or a killed process", () => {
    const source = proofPanelSource;
    //  Every phrase here is one a reader could mistake for a claim MUSTER
    //  does not make. The panel says "VERIFIED GCP REPLAY — NOT LIVE
    //  TELEMETRY" and "CLOUD RUN PROCESS DEATH NOT CLAIMED", so the bare
    //  claims themselves must never appear anywhere in its copy.
    for (const forbidden of [
      //  The disclaimers themselves contain these words, so each pattern
      //  excludes the negation that makes the sentence safe.
      /process death(?! not claimed)/i,
      /process was killed/i,
      /killed the process/i,
      /(?<!not )live telemetry(?! *[—-] *not| not)/i,
      /live stream/i,
      /real payment/i,
      /funds were transferred/i,
      /settled the payment/i,
    ]) {
      expect(source).not.toMatch(forbidden);
    }
    //  And the four disclaimers must be present, not merely implied.
    for (const required of [
      "SANDBOX ONLY",
      "NO REAL FUNDS",
      "UNKNOWN AFTER ACCEPTANCE",
      "CLOUD RUN PROCESS DEATH NOT CLAIMED",
      "VERIFIED GCP REPLAY — NOT LIVE TELEMETRY",
    ]) {
      expect(source).toContain(required);
    }
  });
});
