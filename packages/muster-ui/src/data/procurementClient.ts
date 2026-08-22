import {
  transformProcurementCase,
  type ProcurementCaseViewModel,
  type ProcurementPolicyKey,
} from "./procurementReadModel";

export class HttpProcurementCaseClient {
  constructor(
    private readonly fixedEndpoint = "/cases/procurement-fixed.json",
    private readonly perUnitEndpoint = "/cases/procurement-per-unit.json",
  ) {}

  async load(
    policy: ProcurementPolicyKey,
    signal?: AbortSignal,
  ): Promise<ProcurementCaseViewModel> {
    const endpoint = policy === "FIXED_TOLERANCE" ? this.fixedEndpoint : this.perUnitEndpoint;
    const response = await fetch(endpoint, { signal });
    if (!response.ok) {
      throw new Error(`Procurement policy result unavailable (${response.status})`);
    }
    const model = transformProcurementCase(await response.json());
    if (model.policy.key !== policy) {
      throw new Error(`Procurement endpoint returned ${model.policy.key}, expected ${policy}`);
    }
    return model;
  }
}

export const procurementCaseClient = new HttpProcurementCaseClient();

