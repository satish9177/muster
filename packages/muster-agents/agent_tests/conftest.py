"""Fixtures for the fleet suite.

**Nothing here reaches a network, and nothing here calls a model.**  The
interpreters this suite injects are deterministic ``BaseLlm`` implementations;
the one test that talks to a hosted model is marked ``model`` and skipped unless
an operator opts in with ``MUSTER_LIVE_MODEL``.

PostgreSQL is optional and is exercised where it is the subject.  The worked run
is checked against the in-memory adapter *and* against a real database, and the
first is not a stand-in for the second: it is what makes the fleet's own
regressions run on every commit rather than only where a database is
configured.
"""

from __future__ import annotations

import os
import uuid

import pytest
from demo.cloud_hero import CloudHeroRun

from agent_tests.support import cloud
from muster.platform.adapters.sql.schema import migrate

DSN_VARIABLE = "MUSTER_TEST_DSN"
LIVE_MODEL_VARIABLE = "MUSTER_LIVE_MODEL"

_NO_DATABASE = (
    f"needs a real PostgreSQL instance: set {DSN_VARIABLE}. "
    "The fleet's own behaviour is checked against the in-memory adapter and "
    "does not depend on this."
)
_NO_MODEL = (
    f"calls a hosted model: set {LIVE_MODEL_VARIABLE}=1 and configure an agent "
    "(MUSTER_AGENT_MODEL, GOOGLE_CLOUD_PROJECT, ...) to opt in. This costs money "
    "and needs credentials, so it is never part of an ordinary run."
)


@pytest.fixture(scope="session")
def dsn() -> str:
    configured = os.environ.get(DSN_VARIABLE)
    if not configured:
        pytest.skip(_NO_DATABASE)
    return configured


@pytest.fixture(scope="session")
def migrated_dsn(dsn: str) -> str:
    migrate(dsn)
    return dsn


@pytest.fixture
def tenant_id() -> str:
    """A tenant nothing else uses, so every test exercises the boundary."""
    return f"tenant-{uuid.uuid4().hex[:16]}"


@pytest.fixture
def case_id() -> str:
    return f"case-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="session")
def live_model_enabled() -> bool:
    if os.environ.get(LIVE_MODEL_VARIABLE) != "1":
        pytest.skip(_NO_MODEL)
    return True


@pytest.fixture
def cloud_run(tenant_id: str, case_id: str) -> CloudHeroRun:
    """The cloud composition root, driven against real agents holding deployed keys.

    Here rather than beside one suite because two of them need the same run:
    the acceptance suite asserts on what it decided, and the adversarial suite
    poisons it and looks at what it printed.  Two independently built runs
    would be two cases, and the second suite would be checking a narration of
    something the first never produced.
    """
    return cloud.worked_run(tenant_id, case_id)
