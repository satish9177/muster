import { Boxes, HardHat } from "lucide-react";

export type CaseKind = "workforce" | "procurement";

interface CaseSelectorProps {
  active: CaseKind;
  onSelect: (kind: CaseKind) => void;
}

export function CaseSelector({ active, onSelect }: CaseSelectorProps) {
  return (
    <nav className="case-selector" aria-label="MUSTER demo cases">
      <button
        type="button"
        className={active === "workforce" ? "active" : ""}
        onClick={() => onSelect("workforce")}
      >
        <HardHat size={13} aria-hidden="true" />
        <span>
          <strong>WORKFORCE</strong>
          <small>Ravi · Verified cloud</small>
        </span>
      </button>
      <button
        type="button"
        className={active === "procurement" ? "active" : ""}
        onClick={() => onSelect("procurement")}
      >
        <Boxes size={13} aria-hidden="true" />
        <span>
          <strong>PROCUREMENT</strong>
          <small>PO-4821 · Cross-domain proof</small>
        </span>
      </button>
    </nav>
  );
}

