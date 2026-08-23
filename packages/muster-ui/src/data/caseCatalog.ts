import type { HeroCaseViewModel } from "./readModel";
import type { ProcurementCaseViewModel } from "./procurementReadModel";

export interface CaseCatalogViewModel {
  workforce: {
    domain: "WORKFORCE";
    title: string;
    outcome: string;
    actionAmount: string;
    provenance: string;
    verifiedCloud: boolean;
  };
  procurement: {
    domain: "PROCUREMENT";
    title: string;
    outcome: string;
    provenance: string;
  };
}

export function buildCaseCatalog(
  workforce: HeroCaseViewModel,
  procurement: ProcurementCaseViewModel,
): CaseCatalogViewModel {
  return {
    workforce: {
      domain: "WORKFORCE",
      title: workforce.title,
      outcome: workforce.outcome,
      actionAmount: workforce.action.amount,
      provenance: workforce.provenance.label,
      verifiedCloud: workforce.provenance.mode === "verified-cloud-execution",
    },
    procurement: {
      domain: "PROCUREMENT",
      title: `${procurement.case.po_id} — ${procurement.case.title}`,
      outcome: procurement.result.outcome,
      provenance: procurement.provenance.basis,
    },
  };
}
