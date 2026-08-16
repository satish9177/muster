"""The production codec against the frozen corpus.

Two independent checks, and they prove different things:

* **Round trip over all sixteen vectors.**  The production decoder reads octets
  it has never seen and the production encoder writes them back byte-for-byte,
  and every published digest recomputes.  This exercises the grammar over every
  frozen shape -- including the ones this milestone has no typed model for.
* **Construction from scratch.**  For the types Milestone A does model, the
  value is built from its documented content and encoded.  This is the check
  that a decoder mirroring its own mistakes cannot pass.
"""

from __future__ import annotations

import pytest

from muster.core.actions import Action, ActionField, ConsequentialAction
from muster.core.evidence.relations import ClosedLowerBound
from muster.core.evidence.transcript import AcquisitionPayload
from muster.core.expr.ir import Binary, BinaryOp, Leaf, LitInt
from muster.core.expr.terms import term_digest, term_node
from muster.core.results import Ok
from muster.core.values.scalars import VEnum, VInt, VScaled
from muster.core.values.sorts import IntSort
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind, digest_node, digest_octets
from tests.conftest import GoldenVector

pytestmark = pytest.mark.golden

#  Frozen constants read off the corpus. A mistranscription makes a test fail,
#  never pass, so transcribing them here cannot hide a defect.
PROCUREMENT_ACTION_SCHEMA_DIGEST = (
    "8faab2f735df5380ecc9395112b54849cab2b37d10d795f712a9d925b751ee6c"
)
PROCUREMENT_PREDICATE_SCHEMA_DIGEST = (
    "6021ad9aa694a868155f97e273be30fa14ce00142a881e7bd937b835e4c2a388"
)
PROCUREMENT_REQUEST_ID = "81e78827db80d5e2240e82254c59a2917796b4567af8bec5d5e0506ba061aabb"

ACCEPTED_QUANTITY = SymbolRef("accepted_quantity", ("PO-4471",))

DIGEST_KINDS = {kind.value: kind for kind in DigestKind}


def test_every_frozen_vector_round_trips(golden_vectors: dict[str, GoldenVector]) -> None:
    """The decoder is total over the corpus and the encoder is its inverse."""
    assert len(golden_vectors) == 16
    for vector in golden_vectors.values():
        decoded = decode(vector.octets)
        assert isinstance(decoded, Ok), f"{vector.name} did not decode: {decoded}"
        assert encode(decoded.value) == vector.octets, f"{vector.name} did not re-encode"


def test_every_published_digest_recomputes(golden_vectors: dict[str, GoldenVector]) -> None:
    for vector in golden_vectors.values():
        if vector.digest is None or vector.digest_kind is None:
            continue
        kind = DIGEST_KINDS.get(vector.digest_kind)
        if kind is None:
            #  A domain this milestone has no use for. Reserving one before its
            #  preimage exists is how two domains collide later.
            continue
        assert digest_octets(kind, vector.octets).hex == vector.digest, vector.name


def test_symbol_ref_reproduces_v01(golden_vectors: dict[str, GoldenVector]) -> None:
    vector = golden_vectors["V-01-SymbolRef"]
    assert encode(ACCEPTED_QUANTITY.to_node()) == vector.octets
    assert digest_node(DigestKind.SYMBOL_REF, ACCEPTED_QUANTITY.to_node()).hex == vector.digest
    #  The assertion key a solver label is built from is this digest, in hex.
    assert ACCEPTED_QUANTITY.key() == vector.digest


def test_nested_term_reproduces_v02(golden_vectors: dict[str, GoldenVector]) -> None:
    vector = golden_vectors["V-02-NestedTerm"]
    term = Binary(BinaryOp.GE, Leaf(ACCEPTED_QUANTITY), LitInt(97))
    assert encode(term_node(term)) == vector.octets
    assert term_digest(term).hex == vector.digest


def test_action_reproduces_v04(golden_vectors: dict[str, GoldenVector]) -> None:
    vector = golden_vectors["V-04-Action"]
    action = Action(
        kind="PAY",
        fields=(
            ActionField("recipient", VEnum("party_id", "SUP-12")),
            ActionField("amount", VScaled("INR", 2, 6_300_000)),
            ActionField("basis_code", VEnum("basis", "FIXED")),
        ),
    )
    assert encode(action.to_node()) == vector.octets
    assert action.digest().hex == vector.digest


def test_consequential_action_reproduces_v05(golden_vectors: dict[str, GoldenVector]) -> None:
    """The diagnostic field is dropped, and the schema digest travels with it."""
    vector = golden_vectors["V-05-ConsequentialAction"]
    projected = ConsequentialAction(
        action_schema_digest=Digest(bytes.fromhex(PROCUREMENT_ACTION_SCHEMA_DIGEST)),
        kind="PAY",
        consequential_fields=(
            ActionField("recipient", VEnum("party_id", "SUP-12")),
            ActionField("amount", VScaled("INR", 2, 6_300_000)),
        ),
    )
    assert encode(projected.to_node()) == vector.octets
    assert projected.digest().hex == vector.digest


def test_acquisition_payload_reproduces_v06(golden_vectors: dict[str, GoldenVector]) -> None:
    vector = golden_vectors["V-06-AcquisitionPayload"]
    payload = AcquisitionPayload(
        tenant_id="ALPHA",
        case_id="PO-4471",
        subject="PO-4471",
        proposition=ACCEPTED_QUANTITY,
        relation=ClosedLowerBound(VInt(99)),
        value_sort=IntSort(),
        predicate_schema_digest=Digest(bytes.fromhex(PROCUREMENT_PREDICATE_SCHEMA_DIGEST)),
        observed_at=1_780_272_000_000_000,
        issued_at=1_780_272_060_000_000,
        validity=HalfOpenInterval(1_780_272_000_000_000, 1_780_358_400_000_000),
        nonce=bytes(range(16)),
        source_class="GOODS_RECEIPT_SYSTEM",
        signer_key_ref="key-gr-1",
        authorization_policy_version=3,
        request_id=Digest(bytes.fromhex(PROCUREMENT_REQUEST_ID)),
    )
    assert encode(payload.to_node()) == vector.octets
    assert payload.digest().hex == vector.digest


def test_signing_body_is_the_payload_octets(golden_vectors: dict[str, GoldenVector]) -> None:
    """What a receipt signature covers is exactly the payload encoding.

    Nothing security-critical sits beside the signature, so there is no field an
    attacker could swap while leaving the signature valid.
    """
    assert (
        golden_vectors["V-07-VerificationReceiptSigningBody"].octets
        == golden_vectors["V-06-AcquisitionPayload"].octets
    )


def test_production_digest_kinds_are_declared(declared_digest_kinds: frozenset[str]) -> None:
    """The digest namespace is closed and every kind used here is a frozen one."""
    for kind in DigestKind:
        assert kind.value in declared_digest_kinds, kind.value


def test_record_arities_match_the_frozen_inventory(schema_inventory: dict[str, int]) -> None:
    """Every record this milestone encodes has the frozen tag and arity.

    Checked by encoding real values and reading the arity back out of the
    octets, so the check cannot pass by agreeing with a table somebody typed.
    """
    from tests.support.specimens import every_specimen

    seen = 0
    for node in every_specimen():
        for tag, arity in _records(node):
            expected = schema_inventory.get(tag)
            assert expected is not None, f"{tag} is not a frozen type"
            assert arity == expected, f"{tag} arity {arity} != frozen {expected}"
            seen += 1
    assert seen > 0


def _records(node: object) -> list[tuple[str, int]]:
    from muster.core.wire.nodes import NRec, NSeq, NSet, NTagged

    found: list[tuple[str, int]] = []
    match node:
        case NRec(tag, fields):
            found.append((tag, len(fields)))
            for field in fields:
                found.extend(_records(field))
        case NTagged(_, payload):
            found.extend(_records(payload))
        case NSeq(items):
            for item in items:
                found.extend(_records(item))
        case NSet(members):
            for member in members:
                found.extend(_records(member))
        case _:
            pass
    return found
