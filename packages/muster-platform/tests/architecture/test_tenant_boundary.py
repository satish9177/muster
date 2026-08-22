"""The tenant boundary as a shape, checked without a database.

The behavioural half of this rule lives in ``integration/test_tenant_isolation``
and needs PostgreSQL.  This half does not, and it is the half that makes the
rule structural rather than behavioural: **a tenant-scoped query missing its
tenant qualification is not a bug to catch in review, it is a call that cannot
be spelled.**

What is *not* claimed, here or anywhere: database-level isolation.  There is one
component and one database role in this milestone, so there is no second
principal to fence off, and row-level security enforcing a boundary against a
role that owns every table would be decoration.  The boundary is the API shape
and the primary keys, and saying so is the honest version.
"""

from __future__ import annotations

import dataclasses
import inspect

import pytest

from muster.platform.adapters.sql.database import SqlDatabase, SqlTenantScope
from muster.platform.casework.ports import (
    CaseHeadRepository,
    ContentStore,
    EvidenceRequestRepository,
    TranscriptRepository,
)
from muster.platform.gate.ports import ExecutionRepository

pytestmark = pytest.mark.architecture

TENANT_SCOPED_TABLES = (
    "store.content",
    "casework.case_head",
    "casework.transcript_entry",
    "casework.evidence_request",
    "action_gate.execution",
)


def test_no_repository_method_takes_a_tenant_argument() -> None:
    """A repository does not exist until a tenant has been named.

    So there is no call that could omit it, and no reviewer who has to notice.
    """
    checked = 0
    for protocol in (
        ContentStore,
        TranscriptRepository,
        CaseHeadRepository,
        EvidenceRequestRepository,
        ExecutionRepository,
    ):
        for name, member in vars(protocol).items():
            if name.startswith("_") or not callable(member):
                continue
            parameters = set(inspect.signature(member).parameters)
            assert "tenant_id" not in parameters, f"{protocol.__name__}.{name}"
            assert "tenant" not in parameters, f"{protocol.__name__}.{name}"
            checked += 1
    #  A scan that found no methods would pass vacuously.
    assert checked >= 8


def test_a_transaction_is_opened_for_exactly_one_tenant() -> None:
    """One transaction cannot span two tenants, because it names one to begin."""
    for opener in (SqlDatabase.writing, SqlDatabase.reading):
        assert list(inspect.signature(opener).parameters) == ["self", "tenant_id"]


def test_a_scope_cannot_be_repointed_at_another_tenant() -> None:
    """Frozen, so the tenant a scope was built for is the tenant it stays for."""
    assert {field.name for field in dataclasses.fields(SqlTenantScope)} == {
        "connection",
        "_tenant_id",
    }
    #  A frozen dataclass replaces ``__setattr__`` with one that raises. Asserting
    #  the mechanism rather than the decorator keeps this true if the class is
    #  ever written by hand.
    assert SqlTenantScope.__setattr__ is not object.__setattr__


def test_every_statement_over_a_tenant_scoped_table_names_the_tenant() -> None:
    """Read out of the SQL itself, so a new statement cannot quietly omit it."""
    from muster.platform.adapters.sql import content, executions, head, requests, transcript

    checked = 0
    for module in (content, executions, head, requests, transcript):
        for name, value in vars(module).items():
            if not name.startswith("_") or not isinstance(value, str):
                continue
            if not any(table in value for table in TENANT_SCOPED_TABLES):
                continue
            assert "tenant_id" in value, f"{module.__name__}.{name} does not name the tenant"
            checked += 1
    assert checked >= 8


def test_the_content_store_is_keyed_by_tenant_as_well_as_digest() -> None:
    """Two tenants holding identical octets hold two rows, by primary key.

    Deduplicating across the boundary would make one tenant's retention
    decision another tenant's problem, and would leak the existence of an
    artifact across the boundary that exists to prevent exactly that.
    """
    from muster.platform.adapters.sql.migrations import MIGRATIONS

    creating = [
        statement
        for migration in MIGRATIONS
        for statement in migration.up
        if "CREATE TABLE store.content" in statement
    ]
    assert len(creating) == 1
    assert "PRIMARY KEY (tenant_id, digest)" in creating[0]


def test_every_foreign_key_carries_the_tenant() -> None:
    """A reference that crossed the boundary would have to be spelled to exist.

    Every foreign key in the schema leads with ``tenant_id``, so a row in one
    tenant cannot reference a row in another -- not because it is denied, but
    because the key it would need does not resolve.
    """
    from muster.platform.adapters.sql.migrations import MIGRATIONS

    references = 0
    for migration in MIGRATIONS:
        for statement in migration.up:
            for line in statement.splitlines():
                stripped = line.strip()
                if not stripped.startswith("FOREIGN KEY"):
                    continue
                assert stripped.startswith("FOREIGN KEY (tenant_id,"), stripped
                references += 1
    assert references >= 5
