"""The recording reset is explicit and scoped to one synthetic demo case."""

from __future__ import annotations

from unittest.mock import MagicMock

import psycopg
import pytest
from demo.action_gate_api import DEMO_CASE, DEMO_TENANT
from demo.reset_action_gate import DemoResetRefused, reset_demo_execution


def test_demo_reset_requires_the_exact_explicit_confirmation() -> None:
    with pytest.raises(DemoResetRefused, match="confirmation must exactly match"):
        reset_demo_execution(
            dsn="postgresql://unused",
            confirmation="yes",
        )


def test_demo_reset_deletes_only_the_named_synthetic_tenant_and_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
    cursor.rowcount = 1

    def connect(_dsn: str) -> MagicMock:
        return connection

    monkeypatch.setattr(psycopg, "connect", connect)

    deleted = reset_demo_execution(
        dsn="postgresql://configured",
        confirmation=f"{DEMO_TENANT}/{DEMO_CASE}",
    )

    assert deleted == 1
    cursor.execute.assert_called_once()
    query, parameters = cursor.execute.call_args.args
    assert "DELETE FROM action_gate.execution" in query
    assert "WHERE tenant_id = %s AND case_id = %s" in query
    assert parameters == (DEMO_TENANT, DEMO_CASE)
    assert "TRUNCATE" not in query.upper()
