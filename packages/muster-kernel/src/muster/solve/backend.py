"""The solver port.

Three methods, each with a caller that needs it: ``capabilities`` so ``prepare``
can reject an unsupported fragment before any query is issued, ``check`` for the
question itself, and ``fingerprint`` so a record can say exactly what answered
it.  The kernel depends on this protocol and never on an adapter; only the
composition root chooses which adapter exists.
"""

from __future__ import annotations

from typing import Protocol

from muster.core.values.fingerprint import SolverFingerprint
from muster.solve.query import SolverQuery
from muster.solve.verdict import FragmentCapabilities, SolverVerdict


class SolverBackend(Protocol):
    def capabilities(self) -> FragmentCapabilities: ...

    def fingerprint(self) -> SolverFingerprint: ...

    def check(self, query: SolverQuery) -> SolverVerdict: ...
