import { Boxes, Grid2X2, HardHat } from "lucide-react";

export type CaseKind = "cases" | "workforce" | "procurement";

interface CaseSelectorProps {
  active: CaseKind;
  onSelect: (kind: CaseKind) => void;
}

export function CaseSelector({ active, onSelect }: CaseSelectorProps) {
  return (
    <header className="product-bar">
      <button type="button" className="product-brand" onClick={() => onSelect("cases")} aria-label="MUSTER case catalog">
        <span className="brand-mark" aria-hidden="true">M</span>
        <span><strong>MUSTER</strong><small>ENTERPRISE CASE CONTROL</small></span>
      </button>
      <nav className="product-primary-nav" aria-label="Product navigation">
        <button type="button" className={active === "cases" ? "active" : ""} onClick={() => onSelect("cases")}>
          <Grid2X2 size={13} aria-hidden="true" /> Cases
        </button>
        <span>Fleet</span>
      </nav>
      <nav className="case-selector" aria-label="MUSTER cases">
        <button type="button" className={active === "workforce" ? "active" : ""} onClick={() => onSelect("workforce")}>
          <HardHat size={13} aria-hidden="true" /> Workforce
        </button>
        <button type="button" className={active === "procurement" ? "active" : ""} onClick={() => onSelect("procurement")}>
          <Boxes size={13} aria-hidden="true" /> Procurement
        </button>
      </nav>
    </header>
  );
}
