"""Making a race happen on purpose, with real threads and a real database.

Neither of these is a mock.  ``Rendezvous`` only decides *when* real code runs;
``Interfering`` only decides *what else* runs first, and what it runs is the
same repository the application uses, against the same PostgreSQL.  Every
statement executed in a test that uses these is a statement the production path
executes too -- what is fabricated is the interleaving, which is the only part
a test cannot get deterministically by waiting and hoping.
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field

from muster.platform.casework.ports import CaseworkDatabase, TenantScope

#  Long enough that a slow solver run does not look like a deadlock, short
#  enough that a real deadlock fails the suite instead of hanging it.
RENDEZVOUS_TIMEOUT = 60.0


class Rendezvous:
    """Hold the first ``parties`` callers, release them together, then stand aside.

    A plain barrier is wrong here: an attempt that loses a compare-and-swap
    retries, arrives a second time, and would wait for a partner that has
    already finished. This trips once and is transparent afterwards, so it
    synchronises the race without changing what happens after it.
    """

    def __init__(self, parties: int) -> None:
        self._barrier = threading.Barrier(parties)
        self._tripped = threading.Event()

    def arrive(self) -> None:
        if self._tripped.is_set():
            return
        #  A broken barrier means a partner timed out or went away. The race is
        #  then unforced rather than failed, and letting the caller continue is
        #  right: the assertions after it still have to hold.
        with contextlib.suppress(threading.BrokenBarrierError):
            self._barrier.wait(timeout=RENDEZVOUS_TIMEOUT)
        self._tripped.set()


@dataclass
class Interfering:
    """A real database with a real competing writer wedged in front of writes.

    ``before_write`` runs immediately before each read-write transaction is
    opened, on the calling thread, against its own connection. It is how a test
    says "another writer got there first" without depending on the scheduler.
    """

    inner: CaseworkDatabase
    before_write: Callable[[int], None]
    writes: int = field(default=0)

    def writing(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        self.writes += 1
        self.before_write(self.writes)
        return self.inner.writing(tenant_id)

    def reading(self, tenant_id: str) -> AbstractContextManager[TenantScope]:
        return self.inner.reading(tenant_id)


@contextmanager
def nothing() -> Iterator[None]:
    yield
