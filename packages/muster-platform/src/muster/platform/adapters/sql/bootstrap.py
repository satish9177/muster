"""Explicit PostgreSQL schema bootstrap for operators and deployment jobs.

This module contains the operation, never an import side effect or request-path
action. The executable composition root is ``demo/database_bootstrap.py`` so
the platform package continues to read no ambient environment or command line.

**The runtime grants are part of the operation, not a step after it.** Applying
a migration and granting the runtime role what that migration's tables need are
one thing that has to happen together: migration 7 added ``sandbox_rail`` and
the grant block in ``infra/README.md`` was not re-run, so the runtime role could
not touch the simulated external system at all. The Gate did the right thing
with that -- ``EXECUTOR_EXCEPTION``, UNCERTAIN, no redispatch -- which is
exactly why nothing pointed at the cause. So the grants are applied here, by the
migrator, from :mod:`adapters.sql.runtime_grants`, and read back afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.platform.adapters.sql.runtime_grants import (
    PrivilegeReport,
    apply_runtime_grants,
    privilege_report,
)
from muster.platform.adapters.sql.schema import migrate, require_current_schema


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    applied: tuple[int, ...]
    current: tuple[int, ...]
    #: ``None`` when no runtime role was named, which is the local convention;
    #: a deployment names one and gets a measurement instead of an assumption.
    granted: int | None = None
    runtime: PrivilegeReport | None = None


def bootstrap(dsn: str, *, runtime_role: str | None = None) -> BootstrapResult:
    """Apply missing migrations, grant the runtime role, and prove both.

    The privilege report is read back *after* the grants, read-only, and is the
    thing a caller should decide on: ``apply_runtime_grants`` returning without
    raising says the statements ran, and the report says the database agrees.
    """
    applied = migrate(dsn)
    current = require_current_schema(dsn)
    if runtime_role is None:
        return BootstrapResult(applied, current)
    granted = apply_runtime_grants(dsn, role=runtime_role)
    return BootstrapResult(applied, current, granted, privilege_report(dsn, role=runtime_role))
