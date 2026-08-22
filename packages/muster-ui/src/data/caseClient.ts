import { transformCaseTraceArtifact } from "./caseTraceArtifact";
import { transformHeroCase, type HeroCaseViewModel } from "./readModel";

export interface HeroCaseClient {
  load(signal?: AbortSignal): Promise<HeroCaseViewModel>;
}

export class HttpHeroCaseClient implements HeroCaseClient {
  constructor(
    private readonly executionEndpoint = "/cases/ravi-cloud-execution.json",
    private readonly curatedEndpoint = "/cases/ravi-milestone-f.json",
  ) {}

  async load(signal?: AbortSignal): Promise<HeroCaseViewModel> {
    const execution = await fetch(this.executionEndpoint, { signal });
    if (execution.ok) {
      return transformCaseTraceArtifact(await execution.json());
    }
    if (execution.status !== 404) {
      throw new Error(`Verified execution artifact unavailable (${execution.status})`);
    }

    const curated = await fetch(this.curatedEndpoint, { signal });
    if (!curated.ok) throw new Error(`Curated case example unavailable (${curated.status})`);
    return transformHeroCase(await curated.json());
  }
}

export const heroCaseClient: HeroCaseClient = new HttpHeroCaseClient();
