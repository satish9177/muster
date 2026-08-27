import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ActionGatePanel } from "../components/ActionGatePanel";
import {
  ACTION_GATE_SCHEMA_VERSION,
  gateActionLabel,
  HttpActionGateClient,
  mayInvokeGate,
  reconciliationRequired,
  transformActionGateReadModel,
  wasReconciled,
} from "./actionGate";

function specimen(
  phase: "AUTHORIZED" | "EXECUTED" | "UNCERTAIN" | "FAILED" = "AUTHORIZED",
  reconciliation: Record<string, unknown> = {},
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
      reconciled_at: null,
      reconciled_from: null,
      ...reconciliation,
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
    expect(markup).toContain("POSTGRESQL-BACKED LOCAL SANDBOX ACTION GATE");
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

describe("durable reconciliation provenance", () => {
  it("leaves an ordinary outcome with no provenance and still valid", () => {
    for (const phase of ["AUTHORIZED", "EXECUTED", "UNCERTAIN", "FAILED"] as const) {
      const model = transformActionGateReadModel(specimen(phase));
      expect(model.reconciledAt).toBeNull();
      expect(model.reconciledFrom).toBeNull();
      expect(wasReconciled(model)).toBe(false);
    }
  });

  it("carries DISPATCHED provenance onto a reconciled final outcome", () => {
    for (const phase of ["EXECUTED", "FAILED"] as const) {
      const model = transformActionGateReadModel(
        specimen(phase, { reconciled_at: 1717171717, reconciled_from: "DISPATCHED" }),
      );
      expect(model.reconciledAt).toBe(1717171717);
      expect(model.reconciledFrom).toBe("DISPATCHED");
      expect(wasReconciled(model)).toBe(true);
      expect(reconciliationRequired(model)).toBe(false);
    }
  });

  it("carries UNCERTAIN provenance onto a promoted final outcome", () => {
    for (const phase of ["EXECUTED", "FAILED"] as const) {
      const model = transformActionGateReadModel(
        specimen(phase, { reconciled_at: 1717171718, reconciled_from: "UNCERTAIN" }),
      );
      expect(model.reconciledFrom).toBe("UNCERTAIN");
      expect(reconciliationRequired(model)).toBe(false);
    }
  });

  it("keeps an inspected-but-still-unknown execution reconciliation-required", () => {
    const model = transformActionGateReadModel(
      specimen("UNCERTAIN", { reconciled_at: 1717171719, reconciled_from: "DISPATCHED" }),
    );

    expect(model.durableState).toBe("UNCERTAIN");
    expect(model.finality).toBe("OUTCOME_UNKNOWN");
    expect(reconciliationRequired(model)).toBe(true);
    expect(mayInvokeGate(model)).toBe(false);
    expect(gateActionLabel(model)).toBe("Automatic retry disabled");

    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, { gate: model, unavailableReason: null }),
    );
    expect(markup).toContain("Automatic retry disabled · reconciliation required");
    expect(markup).toContain("No redispatch occurred");
    expect(markup).not.toMatch(/<button/);
  });

  it("reports a reconciled confirmation as observed, never as redispatched", () => {
    const model = transformActionGateReadModel(
      specimen("EXECUTED", { reconciled_at: 1717171720, reconciled_from: "DISPATCHED" }),
    );
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, { gate: model, unavailableReason: null }),
    );

    expect(markup).toContain("EXECUTED ONCE · SANDBOX");
    expect(markup).toContain("Outcome established by inspecting the executor");
    expect(markup).toContain("No redispatch occurred");
    expect(markup).not.toMatch(/<button/);
    expect(markup.toLowerCase()).not.toContain("retry");
  });

  it.each([
    ["a lone source state", { reconciled_from: "DISPATCHED" }, /provenance is incomplete/],
    ["a lone timestamp", { reconciled_at: 1717171721 }, /provenance is incomplete/],
    [
      "a source state outside the reconcilable pair",
      { reconciled_at: 1717171721, reconciled_from: "RESERVED" },
      /execution state is malformed/,
    ],
    [
      "a source state that is the current state",
      { reconciled_at: 1717171721, reconciled_from: "CONFIRMED" },
      /execution state is malformed/,
    ],
    [
      "a negative timestamp",
      { reconciled_at: -1, reconciled_from: "DISPATCHED" },
      /execution state is malformed/,
    ],
    [
      "a fractional timestamp",
      { reconciled_at: 1.5, reconciled_from: "DISPATCHED" },
      /execution state is malformed/,
    ],
    [
      "a string timestamp",
      { reconciled_at: "1717171721", reconciled_from: "DISPATCHED" },
      /execution state is malformed/,
    ],
  ])("fails closed on %s", (_name, reconciliation, expected) => {
    expect(() => transformActionGateReadModel(specimen("EXECUTED", reconciliation))).toThrow(
      expected,
    );
  });

  it("fails closed on provenance an unreserved proposal could not have", () => {
    expect(() =>
      transformActionGateReadModel(
        specimen("AUTHORIZED", { reconciled_at: 1717171722, reconciled_from: "DISPATCHED" }),
      ),
    ).toThrow(/not a legal transition/);
  });

  it("fails closed on a rewrite of UNCERTAIN onto itself", () => {
    expect(() =>
      transformActionGateReadModel(
        specimen("UNCERTAIN", { reconciled_at: 1717171723, reconciled_from: "UNCERTAIN" }),
      ),
    ).toThrow(/not a legal transition/);
  });
});
