import { transformGateProof, type GateProofReadModel } from "./gateProofReadModel";

/**
 * Fetches the tracked final Gate proof.
 *
 * `GET` only, one static file, no backend. The replay-only judge build has no
 * mutation endpoint at all, and this client is the reason it does not need one.
 */
export class HttpGateProofClient {
  constructor(private readonly endpoint = "/cases/ravi-cloud-gate-proof.json") {}

  async load(signal?: AbortSignal): Promise<GateProofReadModel> {
    const response = await fetch(this.endpoint, { method: "GET", signal });
    if (!response.ok) {
      throw new Error(`Final Gate proof unavailable (${response.status})`);
    }
    return transformGateProof(await response.json());
  }
}

export const gateProofClient = new HttpGateProofClient();
