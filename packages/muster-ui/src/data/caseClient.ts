import { transformHeroCase, type HeroCaseViewModel } from "./readModel";

export interface HeroCaseClient {
  load(signal?: AbortSignal): Promise<HeroCaseViewModel>;
}

export class HttpHeroCaseClient implements HeroCaseClient {
  constructor(private readonly endpoint = "/cases/ravi-milestone-f.json") {}

  async load(signal?: AbortSignal): Promise<HeroCaseViewModel> {
    const response = await fetch(this.endpoint, { signal });
    if (!response.ok) {
      throw new Error(`Case read model unavailable (${response.status})`);
    }
    return transformHeroCase(await response.json());
  }
}

export const heroCaseClient: HeroCaseClient = new HttpHeroCaseClient();
