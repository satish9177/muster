import {
  Banknote,
  Binary,
  Building2,
  ClipboardList,
  LockKeyhole,
  MessageSquareText,
  ScanLine,
  type LucideIcon,
} from "lucide-react";

import type { EventKind } from "../data/readModel";

const icons: Record<EventKind, LucideIcon> = {
  claim: MessageSquareText,
  plan: ClipboardList,
  boundary: LockKeyhole,
  agent: Building2,
  rebuild: Binary,
  action: Banknote,
};

interface TraceIconProps {
  kind: EventKind;
  siteAgent?: boolean;
}

export function TraceIcon({ kind, siteAgent = false }: TraceIconProps) {
  const Icon = siteAgent ? ScanLine : icons[kind];
  return <Icon size={17} strokeWidth={1.8} aria-hidden="true" />;
}
