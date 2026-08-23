import { transformRaviEvidence, type RaviEvidenceViewModel } from "./evidenceReadModel";

export interface EvidenceClient {
  load(signal?: AbortSignal): Promise<RaviEvidenceViewModel>;
}

export class HttpEvidenceClient implements EvidenceClient {
  constructor(
    private readonly traceEndpoint = "/cases/ravi-cloud-execution.json",
    private readonly proofEndpoint = "/cases/ravi-evidence-proof.json",
  ) {}

  async load(signal?: AbortSignal): Promise<RaviEvidenceViewModel> {
    const [trace, proof] = await Promise.all([
      fetch(this.traceEndpoint, { signal }),
      fetch(this.proofEndpoint, { signal }),
    ]);
    if (!trace.ok) throw new Error(`Verified execution artifact unavailable (${trace.status})`);
    if (!proof.ok) throw new Error(`Committed path audit unavailable (${proof.status})`);
    return transformRaviEvidence(await trace.json(), await proof.json());
  }
}

export const evidenceClient: EvidenceClient = new HttpEvidenceClient();
