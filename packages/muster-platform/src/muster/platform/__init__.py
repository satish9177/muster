"""The control plane: durable state and the imperative shell around the kernel.

The kernel decides.  This package remembers, and it is allowed to do nothing
else.  Everything here exists to answer one question -- can durable state,
concurrency, retries and restarts surround a pure decision procedure without
changing a single answer it gives -- and every module is shaped by that:

* ``casework`` holds the custody boundary as protocols and the one command that
  moves a case forward: append, rebuild, analyse, publish;
* ``ingest`` decides what may enter the store at all;
* ``orchestration`` is pure.  It reads an analysis and a clock reading and
  returns the next imperative step.  It never decides what policy entails, what
  evidence suffices, or whether anything may be acted on;
* ``adapters`` is the only place a database driver appears.  It holds two
  implementations of the same custody protocols -- PostgreSQL and in-memory --
  and no clock: every operation takes the reading it decides under as an
  argument, so nothing here has a reason to take one for itself.

The dependency runs one way: ``muster.platform`` may import ``muster.core`` and
the layers above it; nothing under ``muster`` outside this package may import
``muster.platform``.  Both halves are checked mechanically.
"""
