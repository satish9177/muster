import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import appSource from "../App.tsx?raw";
import { ActionGatePanel } from "../components/ActionGatePanel";
import caseHeaderSource from "../components/CaseHeader.tsx?raw";
import actionGateSource from "./actionGate.ts?raw";
import asyncClientSource from "./asyncClient.ts?raw";
import caseClientSource from "./caseClient.ts?raw";
import evidenceClientSource from "./evidenceClient.ts?raw";
import evidencePlanClientSource from "./evidencePlanClient.ts?raw";
import gateProofClientSource from "./gateProofClient.ts?raw";
import procurementClientSource from "./procurementClient.ts?raw";
import { resolveRuntimeMode } from "./runtimeMode";

const JUDGE_BUILD = resolveRuntimeMode({});
const DEVELOPER_BUILD = resolveRuntimeMode({ DEV: true });

describe("resolveRuntimeMode", () => {
  it("is replay-only for a production build by default", () => {
    //  This is the case that matters. `npm run build` with no flag is what a
    //  hosted deployment runs, and it must not produce a bundle that offers
    //  to mutate anything.
    expect(resolveRuntimeMode({}).replayOnly).toBe(true);
    expect(resolveRuntimeMode({ DEV: false }).replayOnly).toBe(true);
  });

  it("keeps the local developer control under npm run dev", () => {
    expect(resolveRuntimeMode({ DEV: true }).replayOnly).toBe(false);
  });

  it("takes an explicit flag over the build kind, in both directions", () => {
    expect(resolveRuntimeMode({ VITE_MUSTER_LOCAL_GATE: "true" }).replayOnly).toBe(false);
    expect(
      resolveRuntimeMode({ DEV: true, VITE_MUSTER_LOCAL_GATE: "false" }).replayOnly,
    ).toBe(true);
  });

  it("treats any value other than the exact opt-in as replay-only", () => {
    for (const value of ["TRUE", "1", "yes", "", "maybe"]) {
      expect(resolveRuntimeMode({ VITE_MUSTER_LOCAL_GATE: value }).replayOnly).toBe(true);
    }
  });
});

describe("the replay-only build's Action Gate surface", () => {
  it("names the build instead of reporting a broken sandbox", () => {
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, {
        gate: null,
        unavailableReason: null,
        mode: JUDGE_BUILD,
      }),
    );

    expect(markup).toContain("REPLAY-ONLY JUDGE BUILD");
    expect(markup).toContain("No mutation endpoint is exposed.");
    //  "NOT EXECUTED" here would read as a failed execution of the case rather
    //  than as a build that never had an executor.
    expect(markup).not.toContain("NOT EXECUTED");
    expect(markup).not.toContain("Sandbox unavailable");
    expect(markup).not.toContain("<button");
  });

  it("still reports the real local Gate state in the developer build", () => {
    const markup = renderToStaticMarkup(
      createElement(ActionGatePanel, {
        gate: null,
        unavailableReason: "Local sandbox Action Gate is unavailable",
        mode: DEVELOPER_BUILD,
      }),
    );

    expect(markup).toContain("NOT EXECUTED");
    expect(markup).toContain("Local sandbox Action Gate is unavailable");
    expect(markup).not.toContain("REPLAY-ONLY JUDGE BUILD");
  });
});

describe("the mutation path", () => {
  it("is refused by the client itself in a replay-only bundle", async () => {
    //  Three guards, and this is the one no refactor upstream can walk past.
    //  `runtimeMode` under vitest resolves as a developer build, so the module
    //  source is asserted rather than the live branch: what matters is that the
    //  refusal sits in `request`, which every call goes through.
    expect(actionGateSource).toContain("if (runtimeMode.replayOnly) {");
    expect(actionGateSource).toContain("This build exposes no Action Gate endpoint");
    const guard = actionGateSource.indexOf("if (runtimeMode.replayOnly) {");
    const call = actionGateSource.indexOf("await fetch(url, init)");
    expect(guard).toBeGreaterThan(-1);
    expect(guard).toBeLessThan(call);
  });

  it("is guarded at the client call site as well as at the control", () => {
    const app = appSource;
    const header = caseHeaderSource;
    //  Two independent guards, because one of them will eventually be moved by
    //  a refactor and the hosted bundle must survive that.
    expect(app).toContain("if (runtimeMode.replayOnly) return;");
    expect(header).toContain("runtimeMode.replayOnly ?");
  });

  it("is the only thing that reaches the demo API", () => {
    expect(actionGateSource).toContain("/api/demo");
    for (const source of [
      caseClientSource,
      asyncClientSource,
      evidenceClientSource,
      evidencePlanClientSource,
      procurementClientSource,
      gateProofClientSource,
    ]) {
      expect(source).not.toContain("/api/demo");
    }
  });
});

describe("the Action view's body", () => {
  it("is the cloud proof alone in a replay-only bundle", () => {
    //  The Action screen's subject is one thing: the finished five-execution
    //  Google Cloud proof. A local PostgreSQL Gate notice under it puts a
    //  second, local execution surface on that screen -- and a reader then has
    //  to work out which of the two the receipt above belongs to. In a build
    //  that has no local Gate at all, that notice is asking the reader to
    //  untangle something that is not even there.
    expect(appSource).toContain("{!runtimeMode.replayOnly && (");
    const guard = appSource.indexOf("{!runtimeMode.replayOnly && (");
    const panel = appSource.indexOf("<ActionGatePanel");
    const proof = appSource.indexOf("<CloudGateProof />");
    expect(guard).toBeGreaterThan(-1);
    //  The proof comes first and unconditionally; the local Gate only follows
    //  it, and only behind the guard.
    expect(proof).toBeLessThan(guard);
    expect(guard).toBeLessThan(panel);
  });
});
