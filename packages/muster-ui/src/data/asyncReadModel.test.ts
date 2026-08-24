import { describe, expect, it } from "vitest";

import payload from "../../public/cases/ravi-async-durability.json";
import { parseAsyncDurability } from "./asyncReadModel";

describe("parseAsyncDurability", () => {
  it("accepts the real separate-process PostgreSQL continuity proof", () => {
    const model = parseAsyncDurability(payload);
    expect(model.events[0].process_id).not.toBe(model.events[1].process_id);
    expect(model.events[1].loaded_state.head).toEqual(model.events[0].state.head);
    expect(model.events[1].state.head.revision_number)
      .toBeGreaterThan(model.events[0].state.head.revision_number);
    expect(model.events[1].prior_employer_entry_preserved).toBe(true);
    expect(model.result).toMatchObject({
      outcome: "INVARIANT",
      exact_duration_status: "UNRESOLVED",
      execution: "NOT_EXECUTED",
    });
    expect(model.provenance).toMatchObject({
      label: "LOCAL POSTGRESQL DURABILITY PROOF",
      environment: "SYNTHETIC_DEMO",
      cloud_execution: false,
    });
  });

  it("rejects a same-process or cloud-labelled artifact", () => {
    const sameProcess = structuredClone(payload);
    sameProcess.events[1]!.process_id = sameProcess.events[0]!.process_id;
    expect(() => parseAsyncDurability(sameProcess)).toThrow(/continuity/);

    const cloud = structuredClone(payload) as unknown as Record<string, unknown>;
    (cloud.provenance as Record<string, unknown>).cloud_execution = true;
    expect(() => parseAsyncDurability(cloud)).toThrow(/malformed/);
  });
});
