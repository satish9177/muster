"""What answered a query, and whether the answer can be reproduced.

Solver identity, not analysis outcome.  It lives below the analysis seam so
that the solver port -- the narrowest boundary in the system -- does not
drag actions, cases and evidence through itself into every backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.wire.nodes import NAtom, NInt, Node, NRec
from muster.core.wire.shape import read_atom, read_int, read_rec

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


def read_solver_fingerprint(node: Node) -> SolverFingerprint:
    """The inverse of :meth:`SolverFingerprint.to_node`.

    A fingerprint is a *stored* claim about what answered a query, so something
    has to be able to read one back without asking the backend it names -- which
    is the whole point of having written it down.
    """
    backend, version, seed, logic, budget = read_rec(node, TAG_SOLVER_FINGERPRINT, 5)
    return SolverFingerprint(
        backend=read_atom(backend),
        version=read_atom(version),
        seed=read_int(seed),
        logic=read_atom(logic),
        budget=read_int(budget),
    )
