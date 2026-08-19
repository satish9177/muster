"""The complete reader-side check.  Membership alone is not one of the answers.

An inclusion proof establishes that a disclosed leaf belongs to a committed
record.  It says nothing about **who committed it**, **which policy governed
it**, or **whether disclosing it to this reader was permitted** -- and a view
that is wrong in any of those ways can still have a perfect proof for every
leaf it carries, because the writer built it correctly for a different reader.
A verifier that checks membership and stops is therefore trusting the sender
about everything that actually protects the sender's other participants.

So this checks all of it, in one pass, and reports **every** failure rather than
the first: an operator debugging a rejected view needs to know whether it was
one problem or four, and a suite asserting a specific defect needs to see that
defect rather than whichever check happened to run first.

The reader supplies its own trust inputs -- the pinned policy, the keys it
trusts, and who it believes itself to be.  None of them are taken from the view.
That asymmetry is the point: a view is evidence offered by a sender, and every
question a sender could answer in its own favour is answered from elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.actions import TAG_CONSEQUENTIAL_ACTION
from muster.core.results import Err
from muster.core.wire.codec import decode
from muster.core.wire.digests import Digest
from muster.core.wire.nodes import NAtom, NDigest, NRec
from muster.platform.commit.envelope import (
    CommitmentEnvelope,
    EnvelopeVerifier,
    SignedCommitmentEnvelope,
    signing_preimage,
)
from muster.platform.commit.paths import (
    CERTIFICATE_SCHEMA_VERSION,
    Presence,
    is_dynamic,
    is_optional_in_record,
    path_in_inventory,
    presence_of,
)
from muster.platform.commit.tree import LeafBinding, RootBinding, verify_inclusion
from muster.platform.disclose.audience import AUDITOR
from muster.platform.disclose.policy import find_entry_by_digest
from muster.platform.disclose.views import (
    INFERENCE_NOTICE,
    AuditorView,
    Disclosure,
    ParticipantView,
    View,
)
from muster.policy.artifacts import DisclosureEntry, DisclosurePolicy


class VerificationFailure(Enum):
    #: The envelope names a key the reader does not trust.  Checked separately
    #: from the signature so that "signed by a stranger" is never reported as
    #: "corrupt", and so that a reader cannot satisfy the check by being handed
    #: a key along with the view.
    SIGNER_NOT_TRUSTED = "SIGNER_NOT_TRUSTED"
    #: The signature does not verify over the envelope's canonical encoding.
    ENVELOPE_SIGNATURE_INVALID = "ENVELOPE_SIGNATURE_INVALID"
    #: The envelope belongs to another tenant.  A signer legitimately serves
    #: many tenants, so a valid signature is not evidence about which one.
    TENANT_MISMATCH = "TENANT_MISMATCH"
    #: The envelope belongs to another case of the same tenant.
    CASE_MISMATCH = "CASE_MISMATCH"
    #: The envelope was committed under a certificate schema this reader has no
    #: path inventory for, so it cannot decide what was permitted or required.
    SCHEMA_VERSION_UNSUPPORTED = "SCHEMA_VERSION_UNSUPPORTED"
    #: The envelope pins a different disclosure policy than the one supplied.
    #: The substitution this catches is the sharpest one available to a writer:
    #: build a view under a permissive policy, hand the reader a strict one.
    POLICY_SUBSTITUTED = "POLICY_SUBSTITUTED"
    #: The envelope pins a different *bundle* than the one supplied.  A
    #: disclosure policy is one subartifact of a bundle, so two bundles with
    #: identical policy octets have identical policy digests and different
    #: admissibility descriptors, predicate schemas and action schemas.
    #: Checking the policy alone lets a reader accept a decision taken under a
    #: rulebook they never saw.
    BUNDLE_SUBSTITUTED = "BUNDLE_SUBSTITUTED"
    #: A disclosed leaf contradicts the envelope that carries it -- the bundle
    #: the record says it ran under is not the bundle the envelope pins.  The
    #: two are disclosed to an audience *so that* they can be compared, and
    #: comparing them is this reader's job rather than the recipient's.
    DISCLOSED_PIN_CONTRADICTS_ENVELOPE = "DISCLOSED_PIN_CONTRADICTS_ENVELOPE"
    #: The entry the view names does not resolve in the pinned policy.
    ENTRY_NOT_IN_POLICY = "ENTRY_NOT_IN_POLICY"
    #: The named entry is for a different audience or context than the view
    #: claims.  This is audience relabelling caught from the policy side.
    AUDIENCE_RELABELLED = "AUDIENCE_RELABELLED"
    #: The view is for somebody else.  Caught from the reader's side, because
    #: a view built correctly for another audience is internally perfect.
    AUDIENCE_NOT_THE_READER = "AUDIENCE_NOT_THE_READER"
    #: An auditor view claiming a participant audience, or the reverse.
    VIEW_SHAPE_WRONG_FOR_AUDIENCE = "VIEW_SHAPE_WRONG_FOR_AUDIENCE"
    #: Two disclosures at one path.  Refused rather than deduplicated: the two
    #: carry different values and nothing decides which one the record holds.
    DUPLICATE_DISCLOSED_PATH = "DUPLICATE_DISCLOSED_PATH"
    #: A disclosed path the named entry does not permit.  Every leaf in a tree
    #: has a valid proof, so this is the check that stops a valid proof from
    #: being an authorisation.
    PATH_NOT_PERMITTED = "PATH_NOT_PERMITTED"
    #: A disclosed path outside the frozen inventory entirely.
    PATH_NOT_IN_INVENTORY = "PATH_NOT_IN_INVENTORY"
    #: More disclosures than the envelope says the tree has leaves.
    MORE_DISCLOSURES_THAN_LEAVES = "MORE_DISCLOSURES_THAN_LEAVES"
    #: A leaf that does not recompute, or a proof that does not fold to the
    #: committed root.  One value for all of it, because a reader cannot tell
    #: a mutated value from a mutated sibling and should not pretend to.
    INCLUSION_NOT_PROVED = "INCLUSION_NOT_PROVED"
    #: A path the entry permits, whose presence this reader can decide, and
    #: which the view left out.  Without this, a sender may under-disclose
    #: silently -- and an under-disclosed auditor view is how an audit is
    #: quietly narrowed to the parts somebody wanted audited.
    REQUIRED_PATH_MISSING = "REQUIRED_PATH_MISSING"
    #: The entry says this disclosure reveals a sensitive input by inference
    #: and the view carries no notice, or carries one when it should not.
    INFERENCE_NOTICE_WRONG = "INFERENCE_NOTICE_WRONG"
    #: The named entry governs a different outcome class, or a different
    #: action, than the record the view itself discloses.  Without this, a
    #: writer picks whichever of an audience's rows permits least and
    #: under-discloses inside a view that verifies -- because the required set
    #: is derived from the *named* entry, so naming a thinner one shrinks it.
    ENTRY_NOT_FOR_THIS_OUTCOME = "ENTRY_NOT_FOR_THIS_OUTCOME"
    #: The envelope commits a revision that is not the one the reader is asking
    #: about.  A view of a superseded revision is internally perfect and is not
    #: the case's current state; presenting one as current is replay.
    REVISION_NOT_CURRENT = "REVISION_NOT_CURRENT"


@dataclass(frozen=True, slots=True)
class VerificationError:
    failure: VerificationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ReaderContext:
    """Everything the reader knows independently of the view it is checking.

    Every field here answers a question the sender must not be allowed to
    answer for itself.  A view that supplied its own policy, its own trusted
    keys or its own idea of who the reader is would verify against itself and
    prove nothing.
    """

    policy: DisclosurePolicy
    verifier: EnvelopeVerifier
    trusted_keys: frozenset[str]
    tenant_id: str
    case_id: str
    audience_class: str
    disclosure_context: str
    #: The bundle whose pinned policy this reader holds.  Separate from the
    #: policy digest because a policy is a subartifact: identical policies do
    #: not make identical rulebooks.
    bundle_manifest_digest: Digest
    #: The salted commitment of the revision this reader is asking about.
    #: Required, and deliberately not optional: a reader with no expectation
    #: accepts a view of any revision of this case, which is exactly how a
    #: superseded view gets presented as the current state.  A reader who
    #: genuinely wants a historical artifact names that revision's commitment.
    revision_commitment: Digest


def _outcome_class_shown(disclosed: dict[str, bytes]) -> str | None:
    """The outcome class, if the view was shown the tag that names it."""
    octets = disclosed.get("kernel.outcome.tag")
    if octets is None:
        return None
    node = decode(octets)
    if isinstance(node, Err) or not isinstance(node.value, NAtom):
        return None
    return node.value.text


def _required_paths(permitted: tuple[str, ...], disclosed: dict[str, bytes]) -> frozenset[str]:
    """Which permitted paths this reader can *insist* on seeing.

    A path is required when its presence follows from the inventory alone, or
    from the inventory plus an outcome class the view itself disclosed.  Three
    kinds are deliberately excluded, and each exclusion is a case where
    demanding the leaf would reject a correct view:

    * **dynamic paths** -- a collection member exists because the case has one,
      which no reader can decide;
    * **``action.full``** -- present only when the committing side was handed
      the unprojected action, which is not a property of the outcome;
    * **outcome-conditional paths when the tag was not disclosed** -- the
      reader has no way to know which class applies.
    """
    shown = _outcome_class_shown(disclosed)
    required: set[str] = set()
    for path in permitted:
        if is_dynamic(path) or is_optional_in_record(path):
            continue
        presence = presence_of(path)
        if presence is None:
            continue
        if presence is Presence.ALWAYS or (shown is not None and presence.value == shown):
            required.add(path)
    return frozenset(required)


def _check_authenticity(
    envelope: SignedCommitmentEnvelope, context: ReaderContext
) -> list[VerificationError]:
    failures: list[VerificationError] = []
    key_ref = envelope.envelope.signer_key_ref
    if key_ref not in context.trusted_keys:
        failures.append(
            VerificationError(
                VerificationFailure.SIGNER_NOT_TRUSTED,
                f"envelope signed by {key_ref!r}, which this reader does not trust",
            )
        )
    elif not context.verifier.verify(
        key_ref=key_ref,
        preimage=signing_preimage(envelope.envelope),
        signature=envelope.signature,
    ):
        failures.append(
            VerificationError(
                VerificationFailure.ENVELOPE_SIGNATURE_INVALID,
                f"the signature under {key_ref!r} does not cover this envelope",
            )
        )
    return failures


def _check_binding(envelope: CommitmentEnvelope, context: ReaderContext) -> list[VerificationError]:
    failures: list[VerificationError] = []
    if envelope.tenant_id != context.tenant_id:
        failures.append(
            VerificationError(
                VerificationFailure.TENANT_MISMATCH,
                f"envelope binds tenant {envelope.tenant_id!r}, reader expects "
                f"{context.tenant_id!r}",
            )
        )
    if envelope.case_id != context.case_id:
        failures.append(
            VerificationError(
                VerificationFailure.CASE_MISMATCH,
                f"envelope binds case {envelope.case_id!r}, reader expects {context.case_id!r}",
            )
        )
    if envelope.certificate_schema_version != CERTIFICATE_SCHEMA_VERSION:
        failures.append(
            VerificationError(
                VerificationFailure.SCHEMA_VERSION_UNSUPPORTED,
                f"envelope is schema {envelope.certificate_schema_version}, this reader "
                f"holds the inventory for {CERTIFICATE_SCHEMA_VERSION}",
            )
        )
    if envelope.disclosure_policy_digest != context.policy.digest():
        failures.append(
            VerificationError(
                VerificationFailure.POLICY_SUBSTITUTED,
                "the envelope pins a different disclosure policy than the one supplied",
            )
        )
    if envelope.bundle_manifest_digest != context.bundle_manifest_digest:
        failures.append(
            VerificationError(
                VerificationFailure.BUNDLE_SUBSTITUTED,
                "the envelope pins a different bundle than the one supplied",
            )
        )
    if envelope.revision_commitment != context.revision_commitment:
        failures.append(
            VerificationError(
                VerificationFailure.REVISION_NOT_CURRENT,
                "the envelope commits a different revision of this case than the reader "
                "is asking about",
            )
        )
    return failures


def _check_membership(
    envelope: CommitmentEnvelope, disclosures: tuple[Disclosure, ...]
) -> list[VerificationError]:
    binding = LeafBinding(
        tenant_id=envelope.tenant_id,
        case_commitment=envelope.case_commitment,
        revision_commitment=envelope.revision_commitment,
        certificate_schema_version=envelope.certificate_schema_version,
    )
    root_binding = RootBinding(
        tenant_id=envelope.tenant_id,
        case_id=envelope.case_id,
        revision_commitment=envelope.revision_commitment,
        bundle_manifest_digest=envelope.bundle_manifest_digest,
        certificate_schema_version=envelope.certificate_schema_version,
    )
    failures: list[VerificationError] = []
    for disclosure in disclosures:
        proved = verify_inclusion(
            binding=binding,
            root_binding=root_binding,
            leaf_count=envelope.leaf_count,
            root=envelope.root,
            path=disclosure.path,
            value_octets=disclosure.value_octets,
            salt=disclosure.salt,
            proof=disclosure.proof,
        )
        if not proved:
            failures.append(
                VerificationError(
                    VerificationFailure.INCLUSION_NOT_PROVED,
                    f"{disclosure.path}: the disclosed leaf does not prove against the "
                    f"committed root",
                )
            )
    return failures


def verify_view(view: View, context: ReaderContext) -> tuple[VerificationError, ...]:
    """Every check a recipient must make.  An empty result means accepted."""
    signed = view.envelope
    envelope = signed.envelope
    disclosures = view.disclosures

    failures = _check_authenticity(signed, context)
    failures.extend(_check_binding(envelope, context))
    failures.extend(_check_audience(view, context))

    resolved = find_entry_by_digest(context.policy, view.disclosure_entry_digest)
    if isinstance(resolved, Err):
        failures.append(
            VerificationError(VerificationFailure.ENTRY_NOT_IN_POLICY, resolved.error.detail)
        )
        #  Without the entry there is no permitted set, so redaction and the
        #  required set are undecidable.  Membership still is, and is still
        #  worth reporting: it separates "this is not your view" from "this is
        #  not anybody's view".
        failures.extend(_check_membership(envelope, disclosures))
        return tuple(failures)
    entry = resolved.value

    if (entry.audience_class, entry.disclosure_context) != (
        view.audience_class,
        view.disclosure_context,
    ):
        failures.append(
            VerificationError(
                VerificationFailure.AUDIENCE_RELABELLED,
                f"the named entry is for ({entry.audience_class}, {entry.disclosure_context}) "
                f"but the view claims ({view.audience_class}, {view.disclosure_context})",
            )
        )

    #  A first pass over the disclosures, before the redaction checks, because
    #  the entry has to be tied to the record *it* shows before anything is
    #  read off that entry. Duplicates are refused below; here the later of a
    #  pair simply wins, which cannot help an attacker: it is the same map the
    #  duplicate check then rejects the view for.
    shown = {disclosure.path: disclosure.value_octets for disclosure in disclosures}
    failures.extend(_check_entry_governs(entry, shown))

    disclosed: dict[str, bytes] = {}
    permitted = frozenset(entry.permitted_paths)
    for disclosure in disclosures:
        if disclosure.path in disclosed:
            failures.append(
                VerificationError(
                    VerificationFailure.DUPLICATE_DISCLOSED_PATH,
                    f"{disclosure.path} is disclosed more than once",
                )
            )
            continue
        disclosed[disclosure.path] = disclosure.value_octets
        if not path_in_inventory(disclosure.path):
            failures.append(
                VerificationError(
                    VerificationFailure.PATH_NOT_IN_INVENTORY,
                    f"{disclosure.path} is not a path this schema version can produce",
                )
            )
        elif disclosure.path not in permitted:
            failures.append(
                VerificationError(
                    VerificationFailure.PATH_NOT_PERMITTED,
                    f"{disclosure.path} is disclosed and the named entry does not permit it",
                )
            )

    if len(disclosures) > envelope.leaf_count:
        #  Returned rather than recorded: folding proofs a sender supplied is
        #  work the sender chose the amount of, and past this point there is
        #  nothing left to learn -- a tree cannot have fewer leaves than the
        #  view opens, whatever those leaves turn out to prove.
        failures.append(
            VerificationError(
                VerificationFailure.MORE_DISCLOSURES_THAN_LEAVES,
                f"{len(disclosures)} disclosures against a tree of {envelope.leaf_count} leaves",
            )
        )
        return tuple(failures)

    for path in sorted(_required_paths(entry.permitted_paths, disclosed) - set(disclosed)):
        failures.append(
            VerificationError(
                VerificationFailure.REQUIRED_PATH_MISSING,
                f"{path} is permitted, is present in every record of this shape, and was "
                f"not disclosed",
            )
        )

    failures.extend(_check_disclosed_pins(envelope, disclosed))
    failures.extend(_check_notice(view, entry.reveals_sensitive_input))
    failures.extend(_check_membership(envelope, disclosures))
    return tuple(failures)


def _check_entry_governs(
    entry: DisclosureEntry, disclosed: dict[str, bytes]
) -> list[VerificationError]:
    """The named entry must govern the record this view actually shows.

    The permitted set, the required set and the inference notice are all read
    off the entry the *view* names, so an entry the reader does not otherwise
    tie to the record is an entry the writer gets to choose.  Where one
    audience has a row per outcome class -- which the four-part key makes the
    normal shape -- the writer would pick whichever row permits least, drop the
    leaves it does not permit, and hand over a view that verifies while
    withholding what the audience was entitled to.

    Two bindings close it, and both are only available when the view discloses
    the leaf that carries the answer.  Where it does not -- an audience that is
    not shown the outcome at all -- the check is vacuous, which is correct: a
    reader who cannot see the outcome cannot be told which entry governs it,
    and the redaction and required-set checks still hold against whichever row
    was named.
    """
    failures: list[VerificationError] = []
    shown = _outcome_class_shown(disclosed)
    if shown is not None and entry.outcome_class != shown:
        failures.append(
            VerificationError(
                VerificationFailure.ENTRY_NOT_FOR_THIS_OUTCOME,
                f"the named entry governs {entry.outcome_class!r} and the view discloses an "
                f"outcome of {shown!r}",
            )
        )

    action = disclosed.get("kernel.outcome.action")
    if action is not None:
        kind = _action_kind_shown(action)
        if kind is not None and entry.action_kind != kind:
            failures.append(
                VerificationError(
                    VerificationFailure.ENTRY_NOT_FOR_THIS_OUTCOME,
                    f"the named entry governs the action kind {entry.action_kind!r} and the "
                    f"view discloses a {kind!r} action",
                )
            )
    return failures


def _action_kind_shown(octets: bytes) -> str | None:
    """The action kind a disclosed consequential action names.

    Read positionally out of the frozen record rather than through a typed
    reader: this runs on octets a sender supplied, and a typed read would raise
    on a shape it does not expect where this returns ``None`` and lets the
    membership check refuse the leaf instead.
    """
    node = decode(octets)
    if isinstance(node, Err):
        return None
    record = node.value
    if not isinstance(record, NRec) or record.tag != TAG_CONSEQUENTIAL_ACTION:
        return None
    if len(record.fields) < 2 or not isinstance(record.fields[1], NAtom):
        return None
    return record.fields[1].text


def _check_disclosed_pins(
    envelope: CommitmentEnvelope, disclosed: dict[str, bytes]
) -> list[VerificationError]:
    """A disclosed pin must agree with the envelope that carried it.

    ``bundle.manifest_digest`` and ``revision.bundle_pin`` are disclosed to
    three of the four workforce audiences for one stated reason: so a reader
    can check that the case actually ran under the policy they were handed.
    That check has to be performed by something, and leaving it to the
    recipient means it is performed by nobody.
    """
    failures: list[VerificationError] = []
    for path in ("bundle.manifest_digest", "revision.bundle_pin"):
        octets = disclosed.get(path)
        if octets is None:
            continue
        node = decode(octets)
        if isinstance(node, Err) or not isinstance(node.value, NDigest):
            #  Not a digest at all. The membership check refuses the leaf on its
            #  own; this says nothing further rather than guessing.
            continue
        if node.value.value != envelope.bundle_manifest_digest.octets:
            failures.append(
                VerificationError(
                    VerificationFailure.DISCLOSED_PIN_CONTRADICTS_ENVELOPE,
                    f"{path} names a different bundle than the envelope pins",
                )
            )
    return failures


def _check_audience(view: View, context: ReaderContext) -> list[VerificationError]:
    failures: list[VerificationError] = []
    if (view.audience_class, view.disclosure_context) != (
        context.audience_class,
        context.disclosure_context,
    ):
        failures.append(
            VerificationError(
                VerificationFailure.AUDIENCE_NOT_THE_READER,
                f"the view is for ({view.audience_class}, {view.disclosure_context}); this "
                f"reader is ({context.audience_class}, {context.disclosure_context})",
            )
        )
    if (view.audience_class == AUDITOR) != isinstance(view, AuditorView):
        failures.append(
            VerificationError(
                VerificationFailure.VIEW_SHAPE_WRONG_FOR_AUDIENCE,
                f"a {type(view).__name__} claiming audience {view.audience_class!r}",
            )
        )
    return failures


def _check_notice(view: View, reveals_sensitive_input: bool) -> list[VerificationError]:
    if not isinstance(view, ParticipantView):
        #  An auditor view has no notice field.  The entitlement the notice
        #  warns a participant about is one an auditor already has.
        return []
    expected = INFERENCE_NOTICE if reveals_sensitive_input else None
    if view.inference_notice != expected:
        #  Compared against the exact notice rather than against presence: a
        #  view carrying some other string satisfies "a notice is here" and
        #  tells its recipient nothing.
        return [
            VerificationError(
                VerificationFailure.INFERENCE_NOTICE_WRONG,
                f"the entry sets reveals_sensitive_input={reveals_sensitive_input} and the "
                f"view carries {view.inference_notice!r}",
            )
        ]
    return []


def accepted(failures: tuple[VerificationError, ...]) -> bool:
    """Reads better at a call site than comparing against an empty tuple."""
    return not failures


__all__ = [
    "ReaderContext",
    "VerificationError",
    "VerificationFailure",
    "accepted",
    "verify_view",
]
