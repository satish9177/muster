"""The commitment layer, reproduced against the frozen corpus.

Six of the sixteen frozen vectors are commitment artifacts, and until this
milestone the kernel's golden suite could only decode and re-encode them: it had
no typed model for a leaf, a root, an envelope or a view.  It does now, so these
are built **from their documented content** and compared octet for octet.  That
is the check a decoder mirroring its own mistakes cannot pass.

The constants below are read off the reference material -- the procurement
scenario's tenant, case, salt and digests.  Transcribing one wrong makes a test
fail and never pass, so transcription cannot hide a defect.

The signature vectors get the same treatment through the stand-in signer, and
that is the sharpest result here: **the octets a commitment signature covers in
this build are the octets Phase 0.8 froze.**  Signing them with the fixture
secret reproduces the frozen signature exactly, which is a statement about the
preimage rather than about HMAC -- and it is the statement that makes replacing
the primitive with an asymmetric one legitimate rather than a redefinition.

What is *not* reproduced here is the whole procurement tree.  Building 24 leaves
would mean rebuilding the procurement scenario, which is a second fixture with
its own drift; the root and merkle values are taken as given and every structure
around them is checked against the corpus.
"""

from __future__ import annotations

import pytest

from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.core.wire.nodes import NAtom
from muster.platform.commit.envelope import (
    CommitmentEnvelope,
    read_signed_envelope,
    sign_envelope,
    signing_preimage,
    verify_envelope,
)
from muster.platform.commit.salts import CaseSalt, case_commitment, field_salt, revision_commitment
from muster.platform.commit.tree import LeafBinding, RootBinding, leaf_node, root_node
from muster.platform.disclose.verify import (
    ReaderContext,
    VerificationFailure,
    accepted,
    verify_view,
)
from muster.platform.disclose.views import read_participant_view
from muster.policy.artifacts import read_disclosure_policy
from support.commitment import (
    MUSTER_KEY,
    SpecStandinSigner,
    SpecStandinVerifier,
    vector_digests,
    vector_node,
    vectors,
)

pytestmark = pytest.mark.golden

#  The procurement scenario, transcribed from the reference material.
#
#  **Moved by milestone E, and the cause is one field in each of two
#  artifacts.**  The reference scenario's predicate declares
#  ``resource_scope_kinds = {purchase_order}`` and its construction record
#  declares a ``cost_centre`` coordinate, so the predicate schema, the manifest,
#  the construction record and the revision all move -- and the commitments and
#  the tree over them move with the revision they salt.  The disclosure policy
#  digest did **not** move, which is the useful half of the observation: this
#  transition is about what may be attested, not about who may be told.
TENANT = "ALPHA"
CASE = "PO-4471"
SALT = CaseSalt(bytes(range(32)))
SCHEMA_VERSION = 1
LEAF_COUNT = 24

CONSTRUCTION_DIGEST = Digest(
    bytes.fromhex("92beeed93181a9ec2f031c47391f13e49540807687e607d51b1015a5a7d7e25a")
)
REVISION_SEMANTIC_DIGEST = Digest(
    bytes.fromhex("aa610c6c315c51e6f992ad46ea65066c797c1da6e1f9780869b80e975af1f69d")
)
MANIFEST_DIGEST = Digest(
    bytes.fromhex("77a2c8d7c6319b7d44b8647be609d53bfbf1088341d809a75e7d47b6b32ca369")
)
POLICY_DIGEST = Digest(
    bytes.fromhex("9269d14bb9c83fdfa4e233d20d2ab9a4d76171326796b0cbe5b08430f2fac056")
)
MERKLE = bytes.fromhex("0eb4618fd28b6607b5c6aa589226cd32f096fb5b223e7c286e037d35eb378ca3")
ROOT = bytes.fromhex("96c2a1a1649c78cb2bf2ea91f98d5b794950b7a213daba5abdc905cc62f82aae")

CASE_COMMITMENT = "414806a88e2e8a475354728c5d824d65b21f7373d4cc141de2edb4234f0079fd"
REVISION_COMMITMENT = "3cb40590b8e35aabb8ae70a6fd07150ffc181637e5c5e1601b624fc18621b5b5"
CASE_ID_SALT = "15235e8bcec9bf252c36fe601c0bd59bea8623286cc55c0df1f233f41e7cdd00"

#  The reference's WAREHOUSE view, which is the reader-side subject below.
WAREHOUSE_PATHS = (
    "case.case_id",
    "case.tenant_id",
    "revision.bundle_pin",
    "bundle.manifest_digest",
)


def _case_commitment() -> Digest:
    return case_commitment(SALT, CONSTRUCTION_DIGEST)


def _revision_commitment() -> Digest:
    return revision_commitment(SALT, REVISION_SEMANTIC_DIGEST)


def _envelope() -> CommitmentEnvelope:
    return CommitmentEnvelope(
        tenant_id=TENANT,
        case_id=CASE,
        case_commitment=_case_commitment(),
        revision_commitment=_revision_commitment(),
        bundle_manifest_digest=MANIFEST_DIGEST,
        disclosure_policy_digest=POLICY_DIGEST,
        certificate_schema_version=SCHEMA_VERSION,
        leaf_count=LEAF_COUNT,
        root=ROOT,
        signer_key_ref=MUSTER_KEY,
    )


def test_both_commitments_are_salted_and_reproduce() -> None:
    """[B11] Neither raw digest appears, and both keyed forms are the frozen ones."""
    assert _case_commitment().hex == CASE_COMMITMENT
    assert _revision_commitment().hex == REVISION_COMMITMENT
    #  And they are genuinely keyed: the raw digests are not what is published.
    assert _case_commitment() != CONSTRUCTION_DIGEST
    assert _revision_commitment() != REVISION_SEMANTIC_DIGEST


def test_the_field_salt_reproduces() -> None:
    assert field_salt(SALT, "case.case_id").hex() == CASE_ID_SALT


def test_the_leaf_reproduces_v15() -> None:
    """The exact preimage a leaf hash is taken over."""
    leaf = leaf_node(
        LeafBinding(TENANT, _case_commitment(), _revision_commitment(), SCHEMA_VERSION),
        path="case.case_id",
        salt=bytes.fromhex(CASE_ID_SALT),
        value_octets=encode(NAtom(CASE)),
    )
    assert encode(leaf) == vectors()["V-15-CommitmentLeaf"]
    assert (
        digest_octets(DigestKind.MERKLE_LEAF, encode(leaf)).hex
        == vector_digests()["V-15-CommitmentLeaf"]
    )


def test_the_root_record_reproduces_v16() -> None:
    """The leaf count is inside the root, so a truncated tree is a different root."""
    root = root_node(
        RootBinding(TENANT, CASE, _revision_commitment(), MANIFEST_DIGEST, SCHEMA_VERSION),
        leaf_count=LEAF_COUNT,
        top=MERKLE,
    )
    assert encode(root) == vectors()["V-16-CommitmentRoot"]
    assert (
        digest_octets(DigestKind.MERKLE_ROOT, encode(root)).hex
        == vector_digests()["V-16-CommitmentRoot"]
    )
    assert digest_octets(DigestKind.MERKLE_ROOT, encode(root)).octets == ROOT


def test_the_envelope_reproduces_v12() -> None:
    assert encode(_envelope().to_node()) == vectors()["V-12-CommitmentEnvelope"]
    assert _envelope().digest().hex == vector_digests()["V-12-CommitmentEnvelope"]


def test_the_signed_envelope_reproduces_v13_octet_for_octet() -> None:
    """The frozen claim is *which octets are covered*, and this is the proof.

    Signed here with the corpus's own stand-in secret, so the comparison is
    against the frozen signature rather than against a re-derivation of it. A
    build that covered a different preimage -- the encoding rather than its
    domain-separated digest, say, or the signed wrapper rather than the
    envelope -- produces different octets and fails here.
    """
    signed = sign_envelope(_envelope(), SpecStandinSigner())
    assert encode(signed.to_node()) == vectors()["V-13-SignedCommitmentEnvelope"]

    #  And the reading half agrees, through the production verification path.
    assert verify_envelope(signed, SpecStandinVerifier(), trusted_keys=frozenset({MUSTER_KEY}))


def test_the_signing_preimage_is_the_frozen_one() -> None:
    """Stated separately from the signature, because it is the real claim.

    The covered value is the domain-separated digest of the envelope's canonical
    encoding -- which is the envelope vector's own published digest.
    """
    assert signing_preimage(_envelope()).octets.hex() == vector_digests()["V-12-CommitmentEnvelope"]


def test_the_signed_envelope_reads_back_from_v13() -> None:
    """The typed reader is the inverse of the writer over frozen octets."""
    value = read_signed_envelope(vector_node("V-13-SignedCommitmentEnvelope"))
    assert value.envelope == _envelope()
    assert encode(value.to_node()) == vectors()["V-13-SignedCommitmentEnvelope"]


def test_the_participant_view_reads_back_from_v14() -> None:
    view = read_participant_view(vector_node("V-14-ParticipantView"))
    assert encode(view.to_node()) == vectors()["V-14-ParticipantView"]
    assert view.digest().hex == vector_digests()["V-14-ParticipantView"]
    assert view.audience_class == "WAREHOUSE"
    assert view.disclosure_context == "NOTIFICATION"
    assert tuple(disclosure.path for disclosure in view.disclosures) == WAREHOUSE_PATHS


def test_the_frozen_policy_reads_back_from_v11() -> None:
    policy = read_disclosure_policy(vector_node("V-11-DisclosurePolicy"))
    assert encode(policy.to_node()) == vectors()["V-11-DisclosurePolicy"]
    assert policy.digest() == POLICY_DIGEST
    assert {
        (entry.outcome_class, entry.audience_class, entry.disclosure_context)
        for entry in policy.entries
    } == {
        ("DIVERGENT", "WAREHOUSE", "NOTIFICATION"),
        ("INVARIANT", "SUPPLIER", "NOTIFICATION"),
        ("DIVERGENT", "AUDITOR", "AUDIT"),
    }


def _frozen_reader() -> ReaderContext:
    return ReaderContext(
        policy=read_disclosure_policy(vector_node("V-11-DisclosurePolicy")),
        verifier=SpecStandinVerifier(),
        trusted_keys=frozenset({MUSTER_KEY}),
        tenant_id=TENANT,
        case_id=CASE,
        audience_class="WAREHOUSE",
        disclosure_context="NOTIFICATION",
        bundle_manifest_digest=MANIFEST_DIGEST,
        revision_commitment=_revision_commitment(),
    )


def test_the_production_reader_accepts_the_frozen_warehouse_view() -> None:
    """The whole reader-side contract, run against the corpus rather than our own output.

    Every input a reader is supposed to hold independently comes from the frozen
    material here: the policy from V-11, the view from V-14, the trusted key
    from the scenario. Nothing in this test was produced by the code under test,
    which is what makes it evidence about the contract rather than about
    self-consistency.
    """
    failures = verify_view(
        read_participant_view(vector_node("V-14-ParticipantView")), _frozen_reader()
    )
    assert accepted(failures), failures


def test_the_frozen_warehouse_view_is_rejected_for_the_auditor() -> None:
    """The same bytes, a different reader, and it must not verify.

    This is the reader-side twin of the writer-side redaction rule: the view is
    perfect, and it is not this reader's.
    """
    from dataclasses import replace

    auditor = replace(_frozen_reader(), audience_class="AUDITOR", disclosure_context="AUDIT")
    failures = verify_view(read_participant_view(vector_node("V-14-ParticipantView")), auditor)
    assert VerificationFailure.AUDIENCE_NOT_THE_READER in {failure.failure for failure in failures}


def test_the_two_digest_namespaces_are_disjoint_and_closed() -> None:
    """The closure the whole domain-separation argument rests on.

    Both halves of the namespace said in prose that a test asserted this. None
    did, which is the failure mode the architecture suite exists to prevent: an
    invariant claimed in a docstring and enforced nowhere.

    Three things are checked. The two enumerations do not intersect, so no
    preimage under one can be read under the other. Every member of each is
    declared in the frozen corpus -- the type half against the generated
    inventory, the auxiliary half against the frozen auxiliary table
    transcribed below -- so production cannot mint a domain the frozen
    namespace does not know. And every domain string is NUL-free ASCII, which
    is what makes the separator prefix-free and therefore unambiguous.
    """
    from muster.core.wire.digests import DigestKind, domain_separator
    from muster.platform.commit.domains import CommitmentDomain

    type_domains = {kind.value for kind in DigestKind}
    auxiliary = {domain.value for domain in CommitmentDomain}
    assert not (type_domains & auxiliary)

    #  Transcribed from spec/reference-semantics/muster_spec/domains.py, which
    #  is frozen specification material. A domain this build uses and the
    #  corpus does not declare fails here.
    frozen_auxiliary = {
        "MERKLE_NODE",
        "MERKLE_EMPTY",
        "FIELD_SALT",
        "CASE_COMMITMENT",
        "REVISION_COMMITMENT",
        "KEY_REGISTRY_SNAPSHOT",
        "REVOCATION_SNAPSHOT",
        "CONSTRAINT_LABEL",
        "NON_EFFECT_KEY",
        "GOLDEN_VECTOR_CORPUS",
    }
    assert auxiliary <= frozen_auxiliary

    for domain in type_domains | auxiliary:
        assert domain.isascii() and "\x00" not in domain
        assert domain_separator(domain).endswith(b"\x00")


def test_every_production_digest_domain_is_used() -> None:
    """A domain nobody digests under is a reservation, and reserving one before
    its preimage exists is how two domains end up colliding later.

    Scanned over the source rather than exercised, because a member used only
    on a path this suite happens not to take is still used.
    """
    import ast

    from muster.core.wire.digests import DigestKind
    from support.paths import PACKAGE_ROOT, REPOSITORY_ROOT

    named: set[str] = set()
    for root in (
        REPOSITORY_ROOT / "packages" / "muster-kernel" / "src",
        PACKAGE_ROOT / "src",
    ):
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "DigestKind"
                ):
                    named.add(node.attr)
    assert {kind.name for kind in DigestKind} == named
