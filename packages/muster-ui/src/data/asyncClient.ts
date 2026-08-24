import { parseAsyncDurability, type AsyncDurabilityReadModel } from "./asyncReadModel";

export class HttpAsyncDurabilityClient {
  constructor(private readonly endpoint = "/cases/ravi-async-durability.json") {}

  async load(signal?: AbortSignal): Promise<AsyncDurabilityReadModel> {
    const response = await fetch(this.endpoint, { signal });
    if (!response.ok) throw new Error(`Durability proof unavailable (${response.status})`);
    return parseAsyncDurability(await response.json());
  }
}

export const asyncDurabilityClient = new HttpAsyncDurabilityClient();
