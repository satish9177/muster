import { parseEvidencePlan, type EvidencePlanReadModel } from "./evidencePlanReadModel";

export class HttpEvidencePlanClient {
  constructor(private readonly endpoint = "/cases/ravi-evidence-plan.json") {}

  async load(signal?: AbortSignal): Promise<EvidencePlanReadModel> {
    const response = await fetch(this.endpoint, { signal });
    if (!response.ok) throw new Error(`Evidence plan unavailable (${response.status})`);
    return parseEvidencePlan(await response.json());
  }
}

export const evidencePlanClient = new HttpEvidencePlanClient();
