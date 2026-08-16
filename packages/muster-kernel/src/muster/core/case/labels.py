"""Deterministic constraint labels.

A label has to be stable across runs and machines, unique within a revision, and
short enough for the declared field.  It also has to be readable, because it is
what a certificate reader sees when a constraint contributed to an infeasible
outcome.  So the readable form is used whenever it fits, and a digest-derived
form takes over when it does not -- deterministically, on a declared threshold,
never by truncating a name into ambiguity.
"""

from __future__ import annotations

from muster.core.case.constraints import MAX_LABEL_OCTETS
from muster.core.values.symbols import SymbolRef

_DIGEST_PREFIX_CHARS = 16


def constraint_label(prefix: str, ref: SymbolRef) -> str:
    """``C-ENT:present_on_site(Ravi, Sat)``, or a digest form if that is too long."""
    readable = f"{prefix}:{ref}"
    if len(readable.encode("utf-8")) <= MAX_LABEL_OCTETS:
        return readable
    return f"{prefix}#{ref.key()[:_DIGEST_PREFIX_CHARS]}"
