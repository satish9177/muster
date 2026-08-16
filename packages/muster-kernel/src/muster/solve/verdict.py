"""What a backend may answer, and what it must declare it can handle.

Four answers, and none of them is a bare boolean.  ``True`` would throw away the
model an invariant outcome needs as its witness; ``False`` would throw away the
labels an infeasible outcome needs in order to be informative.

``Unsat`` carries *contributing* labels, not a proof.  An unsatisfiable core is
neither minimal nor stable, and it conflicts with encoding assertions the
certificate never shows, so invariance is honestly described as
solver-replayable rather than independently checkable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.values.scalars import Value
from muster.solve.query import QueryVar

type SolverModel = dict[QueryVar, Value]


class UnknownReason(Enum):
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BACKEND_FAILURE = "BACKEND_FAILURE"


@dataclass(frozen=True, slots=True)
class Sat:
    """A model over world-qualified symbols, total over the declared variables."""

    model: SolverModel


@dataclass(frozen=True, slots=True)
class Unsat:
    contributing_source_constraints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Unknown:
    reason: UnknownReason
    detail: str = ""


@dataclass(frozen=True, slots=True)
class UnsupportedFragment:
    """The query is outside what this backend declared it can decide."""

    detail: str


type SolverVerdict = Sat | Unsat | Unknown | UnsupportedFragment


@dataclass(frozen=True, slots=True)
class FragmentCapabilities:
    """What a backend can decide, declared rather than assumed.

    A one-method port can still carry a fat behavioural contract, and it did:
    the bounded oracle cannot do what a real SMT backend can, and pretending
    otherwise turns an unsupported query into a wrong answer instead of a typed
    rejection at ``prepare``.
    """

    backend: str
    version: str
    requires_finite_domains: bool
    max_enumerated_assignments: int
    supports_enum_sorts: bool = True
    supports_scaled_sorts: bool = True
