"""The artifacts a participant and an auditor actually receive.

A view is an envelope, a claim about who it is for, the identity of the policy
entry it applied, and one disclosure per permitted path -- value octets, that
path's salt, and the inclusion proof.  Nothing else.  In particular it carries
no certificate, no revision, no case salt, and no leaf the named entry does not
permit, and each of those absences is checkable by the recipient rather than
promised by the sender.

**What a withheld leaf looks like: nothing.**  Redaction here is omission, not
substitution, and that is the frozen contract's choice rather than a
convenience.  A placeholder would have to be distinguishable from a real value
that happened to equal it, and any encoding that guarantees that is a second
value grammar to get wrong.  A withheld leaf is still *committed* -- it is
inside the tree, counted in ``leaf_count`` and bound into the root -- so the
recipient can see that the record contains leaves they were not shown, and
cannot learn what they are: the value's salt is ``HMAC(case salt, path)`` and
they hold neither.

**What the entry digest tells its recipient, which is more than its paths.**
A view names the policy entry it applied, by digest, so that the recipient can
find *that exact entry* in the policy they hold and check the disclosure
against it.  The entry's identity covers its whole frozen encoding -- including
``outcome_class`` and ``action_kind``, which are two of the four fields the
lookup is keyed on -- so a recipient who holds the pinned policy can read the
outcome class off the entry even when no leaf disclosed it.

That is a property of the frozen contract rather than of this code, and it is
not removable here: the four-part key is what makes entry selection total over
``AnalysisOutcome``, and the digest is what makes "which entry was applied"
answerable at all.  It is stated because it bounds a privacy claim: an audience
that receives a view at all learns which outcome class the case is in.  What it
does not learn is the outcome's *content* -- the action, the amount, the
witness, the reachable set -- which is what the permitted paths govern.
Closing the channel entirely means a Phase-0.8 change to what the entry digest
covers, and that is a decision for the frozen contract's owner.

**Two view types, one code path.**  ``AuditorView`` differs from
``ParticipantView`` by having no inference notice, because an auditor is
entitled to the inference the notice warns a participant about.  Which one is
built follows the audience's *structural* distinction -- an auditor is resolved
from the operator directory rather than from the case's parties -- and not from
a branch on the role name.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.wire.codec import encode
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NBytes, Node, NRec, NSeq
from muster.core.wire.shape import (
    atom_or_none,
    option_node,
    read_atom,
    read_bytes,
    read_digest,
    read_option,
    read_rec,
    read_seq,
)
from muster.platform.commit.build import CaseCommitment
from muster.platform.commit.envelope import SignedCommitmentEnvelope, read_signed_envelope
from muster.platform.commit.tree import ProofStep, read_proof_step
from muster.platform.disclose.audience import AUDITOR, AudienceClass, DisclosureContext
from muster.platform.disclose.policy import entry_digest
from muster.policy.artifacts import DisclosureEntry

TAG_DISCLOSURE = "Disclosure/v1"
TAG_PARTICIPANT_VIEW = "ParticipantView/v1"
TAG_AUDITOR_VIEW = "AuditorView/v1"

#: The notice a view carries when its entry says the disclosure determines a
#: sensitive input by inference.  A string rather than a flag, because the
#: recipient is the audience for it.
INFERENCE_NOTICE = "DISCLOSED_VALUE_DETERMINES_A_SENSITIVE_INPUT"


@dataclass(frozen=True, slots=True)
class Disclosure:
    """One leaf, opened: what it was, under which salt, and where it sits."""

    path: str
    value_octets: bytes
    salt: bytes
    proof: tuple[ProofStep, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_DISCLOSURE,
            (
                NAtom(self.path),
                NBytes(self.value_octets),
                NBytes(self.salt),
                NSeq(tuple(step.to_node() for step in self.proof)),
            ),
        )


@dataclass(frozen=True, slots=True)
class ParticipantView:
    envelope: SignedCommitmentEnvelope
    audience_class: str
    disclosure_context: str
    disclosure_entry_digest: Digest
    disclosures: tuple[Disclosure, ...]
    inference_notice: str | None

    def to_node(self) -> NRec:
        return NRec(
            TAG_PARTICIPANT_VIEW,
            (
                self.envelope.to_node(),
                NAtom(self.audience_class),
                NAtom(self.disclosure_context),
                self.disclosure_entry_digest.to_node(),
                NSeq(tuple(disclosure.to_node() for disclosure in self.disclosures)),
                option_node(atom_or_none(self.inference_notice)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.PARTICIPANT_VIEW, self.to_node())

    def octets(self) -> bytes:
        return encode(self.to_node())


@dataclass(frozen=True, slots=True)
class AuditorView:
    envelope: SignedCommitmentEnvelope
    audience_class: str
    disclosure_context: str
    disclosure_entry_digest: Digest
    disclosures: tuple[Disclosure, ...]

    def to_node(self) -> NRec:
        return NRec(
            TAG_AUDITOR_VIEW,
            (
                self.envelope.to_node(),
                NAtom(self.audience_class),
                NAtom(self.disclosure_context),
                self.disclosure_entry_digest.to_node(),
                NSeq(tuple(disclosure.to_node() for disclosure in self.disclosures)),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.AUDITOR_VIEW, self.to_node())

    def octets(self) -> bytes:
        return encode(self.to_node())


type View = ParticipantView | AuditorView


def build_view(
    commitment: CaseCommitment,
    *,
    entry: DisclosureEntry,
    audience: AudienceClass,
    context: DisclosureContext,
) -> View:
    """Open exactly the leaves the entry permits, and nothing else.

    A permitted path with no leaf in this record is skipped rather than
    refused: an entry permitting ``kernel.outcome.action`` is silent, not
    wrong, on a divergent case, and refusing would make one policy row unable
    to serve two outcomes it was deliberately written to cover.

    Ordered by the canonical path order the tree is built in, so two runs over
    one committed record produce byte-identical disclosures.
    """
    disclosures: list[Disclosure] = []
    for path in commitment.tree.paths:
        if path not in entry.permitted_paths:
            continue
        opened = commitment.tree.disclosure_of(path)
        if opened is None:  # pragma: no cover - the path came from the tree itself
            continue
        value_octets, salt, proof = opened
        disclosures.append(Disclosure(path, value_octets, salt, proof))

    digest = entry_digest(entry)
    if audience.value == AUDITOR:
        return AuditorView(
            envelope=commitment.signed_envelope,
            audience_class=audience.value,
            disclosure_context=context.value,
            disclosure_entry_digest=digest,
            disclosures=tuple(disclosures),
        )
    return ParticipantView(
        envelope=commitment.signed_envelope,
        audience_class=audience.value,
        disclosure_context=context.value,
        disclosure_entry_digest=digest,
        disclosures=tuple(disclosures),
        inference_notice=INFERENCE_NOTICE if entry.reveals_sensitive_input else None,
    )


#  ---- reading ------------------------------------------------------------


def read_disclosure(node: Node) -> Disclosure:
    path, value_octets, salt, proof = read_rec(node, TAG_DISCLOSURE, 4)
    return Disclosure(
        path=read_atom(path),
        value_octets=read_bytes(value_octets),
        salt=read_bytes(salt),
        proof=read_seq(proof, read_proof_step),
    )


def read_participant_view(node: Node) -> ParticipantView:
    fields = read_rec(node, TAG_PARTICIPANT_VIEW, 6)
    notice = fields[5]
    return ParticipantView(
        envelope=read_signed_envelope(fields[0]),
        audience_class=read_atom(fields[1]),
        disclosure_context=read_atom(fields[2]),
        disclosure_entry_digest=read_digest(fields[3]),
        disclosures=read_seq(fields[4], read_disclosure),
        inference_notice=read_option(notice, read_atom),
    )


def read_auditor_view(node: Node) -> AuditorView:
    fields = read_rec(node, TAG_AUDITOR_VIEW, 5)
    return AuditorView(
        envelope=read_signed_envelope(fields[0]),
        audience_class=read_atom(fields[1]),
        disclosure_context=read_atom(fields[2]),
        disclosure_entry_digest=read_digest(fields[3]),
        disclosures=read_seq(fields[4], read_disclosure),
    )
