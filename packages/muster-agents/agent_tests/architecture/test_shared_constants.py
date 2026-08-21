"""Three constants that exist twice, and the checks that keep the copies equal.

MUSTER duplicates a small number of values across distributions on purpose.
Each duplication is a boundary rather than a failure to factor: a source key
lives with the source, so the agent has its own signer and does not import the
control plane's crypto adapter, which also derives case salts; and the fleet
does not import the kernel's composition layer, so a marker defined there is
restated rather than shared.

**A justified duplicate is still a duplicate**, and every one of these is a
*wire-level agreement* between two processes. If they drift:

* a different algorithm identifier means every receipt an agent signs is
  refused by the verifier, in every case, immediately;
* a different unsigned marker means a claim built by the worker agent is not
  the claim the fixtures and the case-file reader describe;
* a different curve or hash means signatures that verify against nothing.

None of those is subtle when it happens and all of them are silent until then,
which is exactly the shape a test is for. The docstrings beside each constant
say a test holds them together; this is that test.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from muster.agents.keys import ECDSA_P256_SHA256 as AGENT_ALGORITHM
from muster.agents.runtime.claims import UNVERIFIED as AGENT_UNVERIFIED
from muster.application.case_file import UNVERIFIED as KERNEL_UNVERIFIED
from muster.platform.adapters.crypto import ECDSA_P256_SHA256 as PLATFORM_ALGORITHM

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
AGENT_KEYS = REPOSITORY / "packages" / "muster-agents" / "src" / "muster" / "agents" / "keys.py"
PLATFORM_CRYPTO = (
    REPOSITORY
    / "packages"
    / "muster-platform"
    / "src"
    / "muster"
    / "platform"
    / "adapters"
    / "crypto"
    / "__init__.py"
)


def test_the_signature_algorithm_identifier_is_one_string() -> None:
    """What a source signs under and what a verifier accepts.

    ``LocalEcdsaSourceVerifier`` refuses any signature whose algorithm is not
    this exact string, so a drift here does not degrade gracefully: every
    agent-signed receipt in every case stops verifying at once.
    """
    assert AGENT_ALGORITHM == PLATFORM_ALGORITHM == "ECDSA-P256-SHA256"


def test_the_unsigned_marker_is_one_value() -> None:
    """What a statement carries where an attestation carries a signature.

    A claim is inert and is not signature-verified, so this marker is
    provenance rather than a control -- and it says out loud that nothing was
    verified, which is the whole reason it is a named marker instead of an
    empty signature somebody might mistake for a real one.
    """
    assert AGENT_UNVERIFIED == KERNEL_UNVERIFIED
    assert AGENT_UNVERIFIED.algorithm == "UNSIGNED-LOCAL-DEVELOPMENT"
    assert AGENT_UNVERIFIED.octets == b""


def test_both_signers_use_the_same_curve_and_hash() -> None:
    """The identifier agreeing is not enough; the primitives must agree too.

    Two modules could spell ``ECDSA-P256-SHA256`` identically and sign over
    different curves, and the failure would look exactly like a corrupt
    signature. Read from the source of both, because what is being compared is
    what each file *says*, not what a shared import would make trivially true.
    """
    for path in (AGENT_KEYS, PLATFORM_CRYPTO):
        named = _names(path)
        assert "SECP256R1" in named, path.name
        assert "SHA256" in named, path.name


def _names(path: Path) -> set[str]:
    """Every attribute and identifier a module names, for a coarse comparison."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.Name):
            found.add(node.id)
    return found


def test_the_agent_signer_does_not_import_the_control_plane_adapter() -> None:
    """The reason the duplicate exists, asserted rather than assumed.

    The control plane's crypto adapter also derives case salts. An agent one
    import away from it would be an agent one import away from the one secret
    in the system it must never hold.
    """
    text = AGENT_KEYS.read_text(encoding="utf-8")
    assert "muster.platform" not in text
    assert "adapters.crypto" not in text
