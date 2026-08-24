"""The untrusted strings between a Worker model and an inert claim."""

from __future__ import annotations

import asyncio

from agent_tests.support import fleet
from agent_tests.support.models import claiming, scripted
from muster.agents.config import DEFAULT_CLAIM_MODEL
from muster.agents.runtime.claims import UNVERIFIED, CandidateClaim, validate_claims
from muster.core.evidence.transcript import StatementRecord
from muster.core.results import Ok
from muster.core.values.scalars import VBool


def test_capitalized_true_from_gemma_is_accepted_by_the_existing_validator() -> None:
    """The proven hosted model spelling remains part of the claim contract."""
    brief = fleet.worker_brief("ALPHA", "CASE-GEMMA-TRUE")

    validated = validate_claims(
        (CandidateClaim(label="T1", value="True"),),
        targets=brief.labelled(),
    )

    assert isinstance(validated, Ok), validated
    assert len(validated.value) == 1
    assert validated.value[0].value == VBool(True)


def test_gemma_style_worker_output_can_only_become_an_unsigned_inert_statement() -> None:
    """Run the real ADK ClaimAgent over the exact tool arguments seen live."""
    model = scripted(claiming("T1", "True"), name=DEFAULT_CLAIM_MODEL)
    worker = fleet.worker(model=model)

    outcome = asyncio.run(
        worker.interpret(
            fleet.worker_brief("ALPHA", "CASE-GEMMA-INERT"),
            fleet.WORKER_ACCOUNT,
        )
    )

    assert isinstance(outcome, tuple), outcome
    assert len(outcome) == 1
    statement = outcome[0]
    assert type(statement) is StatementRecord
    assert statement.asserted_value == VBool(True)
    assert statement.signature == UNVERIFIED
    assert statement.signature.algorithm == "UNSIGNED-LOCAL-DEVELOPMENT"
    assert statement.signature.octets == b""
    assert not hasattr(statement, "justification")
    assert "source_class" not in StatementRecord.__dataclass_fields__

    # The ClaimAgent has no evidence store, signing key, authority coordinate,
    # or consequence engine through which this statement could become more.
    assert set(worker.__dataclass_fields__) == {"model", "clock", "limits"}
    for capability in ("store", "signer", "source_class", "authority", "kernel", "gate"):
        assert not hasattr(worker, capability)
