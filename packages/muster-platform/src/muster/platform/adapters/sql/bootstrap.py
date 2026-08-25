"""Explicit PostgreSQL schema bootstrap for operators and deployment jobs.

This module contains the operation, never an import side effect or request-path
action. The executable composition root is ``demo/database_bootstrap.py`` so
the platform package continues to read no ambient environment or command line.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.platform.adapters.sql.schema import migrate, require_current_schema


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    applied: tuple[int, ...]
    current: tuple[int, ...]


def bootstrap(dsn: str) -> BootstrapResult:
    """Apply missing migrations and prove the complete ledger is current."""
    applied = migrate(dsn)
    return BootstrapResult(applied, require_current_schema(dsn))
