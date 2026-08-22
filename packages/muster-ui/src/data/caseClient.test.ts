import { afterEach, describe, expect, it, vi } from "vitest";

import { HttpHeroCaseClient } from "./caseClient";
import type { RawHeroCase } from "./readModel";

const curated: RawHeroCase = {
  schema_version: "muster.hero-case/v1",
  case: {
    id: "curated",
    title: "Curated case",
    subject: "RAVI",
    pinned_policy: "example",
    policy_version: "example",
    status: "PROPOSED",
    outcome: "INVARIANT",
    action: {
      kind: "PAY",
      recipient: "RAVI",
      currency: "INR",
      amount_minor: 510000,
      execution: "NOT_EXECUTED",
    },
    unresolved: ["example"],
  },
  provenance: {
    mode: "curated-example",
    label: "CURATED EXAMPLE",
    description: "Not execution evidence",
    basis: "Test fixture",
    captured_at: null,
    capture_available: false,
  },
  events: [],
};

afterEach(() => vi.unstubAllGlobals());

describe("HttpHeroCaseClient", () => {
  it("uses the explicitly distinguishable curated fallback only when the artifact is absent", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 404 }))
      .mockResolvedValueOnce(Response.json(curated));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new HttpHeroCaseClient("/execution", "/curated").load();
    expect(result.provenance.mode).toBe("curated-example");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not hide a malformed present cloud artifact behind the curated example", async () => {
    const malformed = { schema_version: "unknown" };
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(Response.json(malformed));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new HttpHeroCaseClient("/execution", "/curated").load()).rejects.toThrow(/Unsupported/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
