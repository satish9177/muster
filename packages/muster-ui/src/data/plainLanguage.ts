/**
 * Plain-English labels for MUSTER's precise vocabulary.
 *
 * This is a **presentation** layer and nothing else. No identifier here is
 * substituted inside kernel logic, read-model validation, or any artifact: the
 * wire words stay exactly what they were, and every mapping below carries the
 * technical term with it as secondary text rather than replacing it. A reader
 * who knows what `INVARIANT` means must still be able to see the word; a
 * reader who does not must not have to learn it to understand the screen.
 *
 * The pairing is deliberate in one direction only. The plain phrase is the
 * headline because that is what a first-time reader parses in a few seconds;
 * the technical term is the subtitle because that is what makes the claim
 * checkable. Dropping either half is what makes these screens either opaque or
 * unfalsifiable.
 */

export interface PlainTerm {
  /** The primary, first-read label. */
  readonly plain: string;
  /** The exact technical term, shown as secondary text or a tooltip. */
  readonly technical: string;
  /** One sentence of plain English, where a headline is not enough. */
  readonly explanation?: string;
}

export const KERNEL_INVARIANT: PlainTerm = {
  plain: "SAFE TO DECIDE",
  technical: "Kernel result: INVARIANT",
  explanation: "Every remaining possibility leads to the same action.",
};

export const KERNEL_DIVERGENT: PlainTerm = {
  plain: "MORE EVIDENCE REQUIRED",
  technical: "Kernel result: DIVERGENT",
  explanation: "Different possible facts lead to different actions.",
};

export const SOURCE_AUTHORITY_VERIFIED: PlainTerm = {
  plain: "SOURCE AUTHORITY VERIFIED",
  technical: "Q-12",
  explanation: "The institution that signed this fact is allowed to attest it.",
};

export const SOURCE_AUTHORITY_REFUSED: PlainTerm = {
  plain: "SOURCE AUTHORITY REFUSED",
  technical: "Q-12 REFUSED",
  explanation: "A signature is not authority; this source may not attest this fact.",
};

export const HINGE: PlainTerm = {
  plain: "FACT THAT COULD CHANGE THE DECISION",
  technical: "HINGE",
};

export const REACHABLE_ACTIONS: PlainTerm = {
  plain: "POSSIBLE AUTHORIZED OUTCOMES",
  technical: "REACHABLE CONSEQUENTIAL ACTIONS",
};

export const INERT_CLAIM: PlainTerm = {
  plain: "RECORDED CLAIM — CANNOT JUSTIFY ACTION",
  technical: "CLAIM ONLY — INERT",
};

export const ADMISSIBLE_ENVELOPE: PlainTerm = {
  plain: "FACT COMBINATIONS STILL ALLOWED BY EVIDENCE + POLICY",
  technical: "ADMISSIBLE ENVELOPE",
};

/** The system boundary, in one line, everywhere it needs saying. */
export const SYSTEM_BOUNDARY = [
  "Gemini interprets.",
  "Sources attest.",
  "Deterministic MUSTER authorizes.",
] as const;

/**
 * The two ideas a judge should leave with, before exploring anything.
 *
 * They are the two the rest of the product is built to make checkable, so they
 * live on the first screen rather than being discovered on the fourth.
 */
export const HEADLINE_IDEAS = [
  "MUSTER asks only for evidence capable of changing the action.",
  "If an irreversible action may already have happened, MUSTER reconciles instead of retrying it.",
] as const;

/** Map a kernel outcome word onto its plain-English pair. */
export function kernelOutcomeTerm(outcome: string): PlainTerm {
  if (outcome === "INVARIANT") return KERNEL_INVARIANT;
  if (outcome === "DIVERGENT") return KERNEL_DIVERGENT;
  return { plain: outcome, technical: `Kernel result: ${outcome}` };
}

/** Map a Q-12 verdict onto its plain-English pair. */
export function authorityTerm(passed: boolean): PlainTerm {
  return passed ? SOURCE_AUTHORITY_VERIFIED : SOURCE_AUTHORITY_REFUSED;
}
