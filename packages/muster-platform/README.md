# muster-platform

The MUSTER control plane: durable case custody and the imperative shell around
the deterministic kernel.

The kernel decides. This package remembers, and it is allowed to do nothing
else. It exists to answer one question — can durable state, concurrency,
retries and restarts surround a pure decision procedure without changing a
single answer it gives — and the suite is organised around that question rather
than around the code.

## Layout

```
src/muster/platform/
  casework/       ports.py   the custody boundary, as protocols naming no database
                  snapshot.py  stored octets -> the values ``rebuild`` takes
                  advance.py   TX A / analyse / TX B, with a bounded CAS retry
                  commands.py  OpenCase, AppendTranscriptEntry, GetCaseStatus
  ingest/         admission.py  binding verification and store admission
  orchestration/  decisions.py  the closed union of imperative steps
                  decide.py     pure: (revision, certificate, now) -> Decision
                  status.py     pure: the derived case status, never a column
  adapters/       clock.py      the only module that reads a clock
                  sql/          the only subtree that imports a database driver
```

## Running the tests

Most of what this package claims is a claim about **PostgreSQL** — transaction
boundaries, compare-and-swap, insert-if-absent, and what two concurrent writers
do to one case. Those claims are not checked against another engine, because a
claim about PostgreSQL verified against SQLite is not evidence. The tests that
need a real instance are skipped, loudly, without one:

```sh
export MUSTER_TEST_DSN='postgresql://user:password@host:port/database'
python -m pytest packages/muster-platform/tests
```

Any PostgreSQL 14+ will do. A throwaway one, if you have Docker:

```sh
docker run -d --name muster-pg -p 55432:5432 \
    -e POSTGRES_USER=muster -e POSTGRES_PASSWORD=muster -e POSTGRES_DB=muster \
    postgres:16-alpine
export MUSTER_TEST_DSN='postgresql://muster:muster@127.0.0.1:55432/muster'
```

Nothing in this repository requires Docker, and no Dockerfile ships with it.
That command is a convenience for running the suite, not part of the design.

The schema is applied by the suite itself, once per session. Tests isolate
themselves by tenant rather than by truncating, which is faster and has the
pleasant side effect that the tenant boundary is exercised by every test in the
suite rather than only by the ones about it.

**Run one copy at a time against a given database.** The acceptance and
failure-injection suites use the Ravi fixture's own tenant and clear it first,
because the frozen milestone-B digests are digests *of that tenant* and no
other one reproduces them. Two concurrent runs will erase each other's state.

Without `MUSTER_TEST_DSN` the pure suites still run: the orchestrator, the
clock, the migration static guards and every architecture contract.

## Import contracts

Two configurations, run with different sets of packages importable, because the
rules point in different directions:

```sh
# the kernel's own matrix, checked against a graph the platform is not in
PYTHONPATH=packages/muster-kernel/src \
    lint-imports --config importlinter.ini

# the rules that span both distributions, including "the kernel never sees the
# control plane"
PYTHONPATH="packages/muster-kernel/src:packages/muster-platform/src" \
    lint-imports --config importlinter-platform.ini
```

On Windows, separate the two paths with `;` instead of `:`.
