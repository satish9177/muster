"""How a proposition may be established, and by whom.

These two classifications carry the OBSERVATION → NORMATIVE barrier.  They are
declared in the authenticated bundle predicate schema, never chosen by a case
builder, which is what stops a caller labelling a normative conclusion as an
attestable record and having the generic kernel believe it.
"""

from __future__ import annotations

from enum import Enum


class EvidenceLayer(Enum):
    """What kind of thing a proposition is."""

    OBSERVATION = "OBSERVATION"
    RECORD = "RECORD"
    NORMATIVE = "NORMATIVE"


class AcquisitionClass(Enum):
    """Whether a source may attest a proposition, or only policy may derive it."""

    ATTESTABLE = "ATTESTABLE"
    DERIVED = "DERIVED"
