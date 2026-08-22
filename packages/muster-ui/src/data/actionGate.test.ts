import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActionGatePanel } from "../components/ActionGatePanel";
import {
  ACTION_GATE_SCHEMA_VERSION,
  gateActionLabel,
  HttpActionGateClient,
  mayInvokeGate,
  transformActionGateReadModel,
} from "./actionGate";

function specimen(
  phase: "AUTHORIZED" | "EXECUTED" | "UNCERTAIN" | "FAILED" = "AUTHORIZED",
): Record<string, unknown> {
  const states = {
    AUTHORIZED: {
      durable_state: null,
      finality: "DEFINITELY_NOT_EXECUTED",
      execution_id: null,
      external_reference: null,
      lifecycle: ["AUTHORIZED"],
      dispatch_count: 0,
    },
    EXECUTED: {
      durable_state: "CONFIRMED",
      finality: "DEFINITELY_EXECUTED",
      execution_id: "ab".repeat(32),
      external_reference: "sandbox-pay-abababababababababababab",
      lifecycle: ["AUTHORIZED", "RESERVED", "DISPATCHED", "CONFIRMED", "EXECUTED"],
      dispatch_count: 1,
    },
    UNCERTAIN: {
      durable_state: "UNCERTAIN",
      finality: "OUTCOME_UNKNOWN",
      execution_id: "cd".repeat(32),
      external_reference: null,
      lifecycle: ["AUTHORIZED", "RESERVED", "DISPATCHED", "UNCERTAIN"],
      dispatch_count: 1,
    },
    FAILED: {
      durable_state: "FAILED",
      finality: "DEFINITELY_NOT_EXECUTED",
      execution_id: "ef".repeat(32),
      external_reference: null,
      lifecycle: ["AUTHORIZED", "RESERVED", "DISPATCHED", "FAILED"],
      dispatch_count: 1,
    },
  } as const;
  return {
    schema_version: ACTION_GATE_SCHEMA_VERSION,
    case_id: "CASE-RAVI-SAT-CLOUD",
    proposal_id: "01".repeat(32),
    proposal: { status: "PROPOSED", outcome: "INVARIANT" },
    execution: {
      phase,
      ...states[phase],
      automatic_retry: false,
      existing_confirmation_returned: phase === "EXECUTED",
    },
    provenance: {
      evidence_agent_path: "VERIFIED GOOGLE CLOUD EXECUTION REPLAY",
      action_execution: "LOCAL DETERMINISTIC SANDBOX EXECUTION",
      execution_principal: "local-ui-sandbox-operator",
      sandbox: true,
      real_funds_transferred: false,
    },
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("Action Gate client and read model", () => {
  it("submits only the opaque proposal reference and no authority-bearing body", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(specimen("EXECUTED")));
    vi.stubGlobal("fetch", fetchMock);
    const proposalId = "01".repeat(32);

    await new HttpActionGateClient("/api/demo").execute("CASE-RAVI-SAT-CLOUD", proposalId);

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(`/api/demo/cases/CASE-RAVI-SAT-CLOUD/proposals/${proposalId}/execute`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
    expect(JSON.stringify([url, init])).not.toMatch(/recipient|amount|currency|action_kind/i);
  });

  it("renders the synthetic reference and explicitly denies real-funds provenance", () => {
    const model = transformActionGateReadModel(specimen("EXECUTED"));
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, { gate: model, unavailableReason: null }),
    );

    expect(markup).toContain("EXECUTED ONCE · SANDBOX");
    expect(markup).toContain("sandbox-pay-abababababababababababab");
    expect(markup).toContain("No real funds transferred");
    expect(markup.toLowerCase()).not.toContain(["payment", "sent"].join(" "));
    expect(markup.toLowerCase()).not.toContain(["money", "transferred"].join(" "));
    expect(markup.toLowerCase()).not.toContain(["bank", "payment", "completed"].join(" "));
  });

  it("renders uncertain as reconciliation-required and exposes no retry action", () => {
    const model = transformActionGateReadModel(specimen("UNCERTAIN"));
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, { gate: model, unavailableReason: null }),
    );

    expect(markup).toContain("Automatic retry disabled · reconciliation required");
    expect(mayInvokeGate(model)).toBe(false);
    expect(gateActionLabel(model)).toBe("Automatic retry disabled");
  });

  it("renders definite failure separately from uncertainty", () => {
    const model = transformActionGateReadModel(specimen("FAILED"));
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, { gate: model, unavailableReason: null }),
    );

    expect(markup).toContain("FAILED");
    expect(markup).toContain("Definitely not executed");
    expect(markup).not.toContain("Reconciliation required");
  });

  it("fails closed when an executed model lacks its durable confirmation", () => {
    const malformed = specimen("EXECUTED");
    const execution = malformed.execution as Record<string, unknown>;
    execution.external_reference = null;

    expect(() => transformActionGateReadModel(malformed)).toThrow(/durable confirmation/);
  });
});
