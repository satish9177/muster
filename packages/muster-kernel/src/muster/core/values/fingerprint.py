"""What answered a query, and whether the answer can be reproduced.

Solver identity, not analysis outcome.  It lives below the analysis seam so
that the solver port -- the narrowest boundary in the system -- does not
drag actions, cases and evidence through itself into every backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.wire.nodes import NAtom, NInt, NRec

TAG_SOLVER_FINGERPRINT = "SolverFingerprint/v1"


class DeterminismClass(Enum):
    REPRODUCIBLE = "REPRODUCIBLE"
    NON_REPRODUCIBLE = "NON_REPRODUCIBLE"


@dataclass(frozen=True, slots=True)
class SolverFingerprint:
    """Exactly which backend, at which version, under which budget."""

    backend: str
    version: str
    seed: int
    logic: str
    budget: int

    def to_node(self) -> NRec:
        return NRec(
            TAG_SOLVER_FINGERPRINT,
            (
                NAtom(self.backend),
                NAtom(self.version),
                NInt(self.seed),
                NAtom(self.logic),
                NInt(self.budget),
            ),
        )
