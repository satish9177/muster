"""Pinned disclosure policy, participant views and the privacy properties.

NON-PRODUCTION SPECIFICATION MATERIAL.

[N1a] `action_disclosable` is gone.  `permitted_paths` is the sole authority, so
a boolean and a path list can no longer contradict each other.

[N1b] The lookup key is `(outcome_class, action_kind, audience_class,
disclosure_context)`.  `outcome_class` is total over `AnalysisOutcome`, which the
Phase 0.7 key was not: `Divergent` has a set of reachable kinds and `Infeasible`
and `Indeterminate` have none at all, so keying on `action_kind` alone had no
total selection function.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .digests import digest_node
from .merkle import Tree, verify_disclosure
from .nodes import Atom, Bytes, Digest, Node, Rec, Seq, Tagged, encode, none, some
from .registry import REG
from .paths import outcome_class, path_in_inventory

if TYPE_CHECKING:
    from .signing import Keyring


class DisclosureError(Exception):
    pass


class DisclosurePolicyConflict(DisclosureError):
    pass


class DisclosurePolicyIncomplete(DisclosureError):
    pass


class UnacknowledgedInferenceDisclosure(DisclosureError):
    pass


class UnknownCommitmentPath(DisclosureError):
    pass


def action_kind_of(outcome: Node) -> Node:
    """Option[ATOM]: Some(kind) exactly when the outcome names one action."""
    assert isinstance(outcome, Tagged)
    if outcome.variant == "Invariant":
        assert isinstance(outcome.value, Rec)
        conseq = outcome.value.fields[0]
        assert isinstance(conseq, Rec)
        return some(conseq.fields[1])
    return none()


def entry_key(entry: Rec) -> tuple[bytes, bytes, bytes, bytes]:
    oc, ak, aud, ctx = entry.fields[0], entry.fields[1], entry.fields[2], entry.fields[3]
    return (encode(oc), encode(ak), encode(aud), encode(ctx))


def validate_policy(policy: Rec, ratifications: set[bytes]) -> None:
    """L-10 uniqueness and L-11 acknowledgement, at bundle load."""
    entries = policy.fields[1]
    assert isinstance(entries, Seq)
    seen: dict[tuple, int] = {}
    for i, e in enumerate(entries.items):
        assert isinstance(e, Rec)
        key = entry_key(e)
        if key in seen:
            raise DisclosurePolicyConflict(
                f"entries {seen[key]} and {i} share a key; never resolved by order or recency"
            )
        seen[key] = i

        oc, ak = e.fields[0], e.fields[1]
        assert isinstance(oc, Atom) and isinstance(ak, Tagged)
        # [N1b] action_kind is Some exactly for INVARIANT.
        if (oc.value == "INVARIANT") != (ak.variant == "Some"):
            raise DisclosurePolicyIncomplete(
                f"entry {i}: action_kind must be Some iff outcome_class = INVARIANT"
            )

        for p in e.fields[6].items:  # type: ignore[union-attr]
            assert isinstance(p, Atom)
            if not path_in_inventory(p.value):
                raise UnknownCommitmentPath(f"entry {i} permits unknown path {p.value!r}")

        reveals = e.fields[4]
        ack = e.fields[5]
        assert isinstance(reveals, type(reveals))
        if getattr(reveals, "value", False) is True:
            if not (isinstance(ack, Tagged) and ack.variant == "Some"):
                raise UnacknowledgedInferenceDisclosure(f"entry {i} lacks an acknowledgement")
            assert isinstance(ack.value, Digest)
            if ack.value.raw not in ratifications:
                raise UnacknowledgedInferenceDisclosure(
                    f"entry {i} acknowledgement does not resolve in the bundle"
                )


def resolve_entry(
    policy: Rec, outcome: Node, audience_class: str, disclosure_context: str
) -> Rec:
    want = (
        encode(Atom(outcome_class(outcome))),
        encode(action_kind_of(outcome)),
        encode(Atom(audience_class)),
        encode(Atom(disclosure_context)),
    )
    entries = policy.fields[1]
    assert isinstance(entries, Seq)
    hits = [e for e in entries.items if isinstance(e, Rec) and entry_key(e) == want]
    if not hits:
        raise DisclosurePolicyIncomplete(
            f"no entry for ({outcome_class(outcome)}, {audience_class}, {disclosure_context})"
        )
    if len(hits) > 1:  # pragma: no cover - validate_policy already rejects this
        raise DisclosurePolicyConflict("multiple effective entries")
    return hits[0]


# --------------------------------------------------------------------------
# view construction
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ViewBundle:
    signed_envelope: Rec
    view: Rec


def build_participant_view(
    tree: Tree,
    signed_envelope: Rec,
    entry: Rec,
    audience_class: str,
    disclosure_context: str,
    inference_notice: str | None,
) -> Rec:
    permitted = [p.value for p in entry.fields[6].items]  # type: ignore[union-attr]
    disclosures = []
    for path in sorted(permitted, key=lambda p: encode(Atom(p))):
        if path not in tree.paths:
            continue  # committed set does not contain this path for this outcome
        i = tree.index_of(path)
        disclosures.append(
            Rec(
                "Disclosure/v1",
                [
                    Atom(path),
                    Bytes(tree.values[i]),
                    Bytes(tree.salts[i]),
                    Seq(
                        [
                            Rec("ProofStep/v1", [Atom(side), Bytes(sib)])
                            for side, sib in tree.proof(path)
                        ]
                    ),
                ],
            )
        )
    return Rec(
        "ParticipantView/v1",
        [
            signed_envelope,
            Atom(audience_class),
            Atom(disclosure_context),
            digest_node("DISCLOSURE_ENTRY", entry),
            Seq(disclosures),
            none() if inference_notice is None else some(Atom(inference_notice)),
        ],
    )


def verify_view(
    view: Rec,
    keyring: "Keyring",
    policy: Rec,
    *,
    trusted_signer: str,
) -> list[str]:
    """The COMPLETE reader-side check.  Returns failures; empty means accepted.

    Found by adversarial review: the earlier version checked only Merkle
    membership, so it accepted a view whose envelope signature was invalid, and a
    view that disclosed seven paths beyond what the disclosure entry it named
    permitted -- including `kernel.outcome.tag` and `kernel.outcome.reachable` to
    a WAREHOUSE audience.  Every leaf proved membership, so nothing objected.

    That is the B11/N1 failure surviving as a READER-side variant: the writer
    redacts correctly, and nothing on the reading side requires it to have done
    so.  Membership proves a leaf belongs to a committed record.  It says nothing
    about who committed it, or whether disclosing it was permitted.  Both must be
    checked here, or a participant is trusting the sender.
    """
    from .signing import verify_record

    failures: list[str] = []

    signed_envelope = view.fields[0]
    assert isinstance(signed_envelope, Rec)
    envelope = signed_envelope.fields[0]
    assert isinstance(envelope, Rec)
    audience, context, entry_digest, disclosures = (
        view.fields[1],
        view.fields[2],
        view.fields[3],
        view.fields[4],
    )
    assert isinstance(audience, Atom) and isinstance(context, Atom)
    assert isinstance(entry_digest, Digest) and isinstance(disclosures, Seq)

    # 1. AUTHENTICITY.  Merkle consistency is not provenance.
    if not verify_record(REG, keyring, signed_envelope, "SignedCommitmentEnvelope"):
        failures.append("envelope signature does not verify")
    signer = envelope.fields[9]
    assert isinstance(signer, Atom)
    if signer.value != trusted_signer:
        failures.append(
            f"envelope signed by {signer.value!r}, not the trusted signer {trusted_signer!r}"
        )

    # 2. POLICY BINDING.  The named entry must exist in the pinned policy ...
    if envelope.fields[5] != digest_node("DISCLOSURE_POLICY", policy):
        failures.append("envelope names a different disclosure policy than the one supplied")
    entries = policy.fields[1]
    assert isinstance(entries, Seq)
    named = [
        e for e in entries.items
        if isinstance(e, Rec) and digest_node("DISCLOSURE_ENTRY", e) == entry_digest
    ]
    if len(named) != 1:
        failures.append(
            f"the disclosure entry the view names resolves to {len(named)} entries in the "
            f"pinned policy"
        )
        return failures
    entry = named[0]

    # ... and must be the entry for this audience and context.
    if entry.fields[2] != audience or entry.fields[3] != context:
        failures.append(
            f"the named entry is for ({entry.fields[2].value}, {entry.fields[3].value}), "
            f"but the view claims ({audience.value}, {context.value})"
        )

    # 3. REDACTION.  Every disclosed path must be permitted by that entry.
    permitted = {p.value for p in entry.fields[6].items}  # type: ignore[union-attr]
    for d in disclosures.items:
        assert isinstance(d, Rec)
        path = d.fields[0]
        assert isinstance(path, Atom)
        if path.value not in permitted:
            failures.append(f"discloses {path.value!r}, which the named entry does not permit")

    # 4. MEMBERSHIP.  Each disclosed leaf belongs to the committed record.
    for d in disclosures.items:
        assert isinstance(d, Rec)
        path, value_bytes, salt, proof = d.fields
        assert isinstance(path, Atom) and isinstance(value_bytes, Bytes)
        assert isinstance(salt, Bytes) and isinstance(proof, Seq)
        steps = [
            (s.fields[0].value, s.fields[1].value)  # type: ignore[union-attr]
            for s in proof.items
        ]
        if not verify_disclosure(envelope, path.value, value_bytes.value, salt.value, steps):
            failures.append(f"{path.value}: inclusion proof does not verify against the root")

    return failures


def view_contains(view: Rec, needle: bytes) -> bool:
    """Privacy probe: does the encoded view contain these octets anywhere?"""
    return needle in encode(view)
