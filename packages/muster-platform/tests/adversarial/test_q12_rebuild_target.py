"""Q-12(a)'s target half, re-established at rebuild and not inherited.

The property, stated as the thing that must not be true:

    **durable transcript membership is not by itself sufficient to turn an
    attestation into consequential evidence.**

Check Q-12(a) has two halves (**section 12.4.3**): the bundle must permit the
class for the predicate, *and* where the payload cites a ``request_id``, the
class must be in that ``EvidenceTarget``'s permitted set.  The architecture
says Q-12(a)...(f) runs **at rebuild** and again independently in the Gate, and
that the rebuild re-evaluates from the pinned artifacts rather than inheriting
the control plane's verdict.

Before this file, the target half ran at admission and nowhere else.  So an
entry that reached the transcript by any route other than today's admission
path -- an operator with SQL, an entry admitted under a request that was
outstanding then and is not now, a future replay of a transcript whose
admission code has changed -- would be lowered into a fact on every rebuild
with the request's narrowing never consulted again.  "It is in the transcript"
was enough, and the whole architecture of the milestone says it must not be.

**What is checked where, and why the split is not a gap.**  A rebuild cannot
be driven by what the case has *outstanding*: outstanding-ness moves as the
head moves, so a replay that consulted it would decide a settled case by what
is being asked today.  What a rebuild can do -- and now does -- is resolve the
digest the receipt itself cites, content-addressed, and apply the narrowing of
the request it names.  A signer who cites a digest naming nothing therefore
escapes the narrowing *here*, and is refused at admission, where the check is
driven by the case's outstanding set and reads no field the signer controls.
Neither layer is redundant and neither is sufficient alone.
"""

from __future__ import annotations

from dataclasses import replace

from muster.application.rebuild import rebuild, transcript_prefix
from muster.core.case.facts import AttestedBy
from muster.core.case.revision import RebuildInputs
from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget
from muster.core.evidence.transcript import Attestation
from muster.core.results import Ok
from muster.core.values.classification import AcquisitionClass
from muster.policy.manifest import LoadedBundle
from support import authority as A
from support import ravi
from support.ravi import RaviCase

#  Not a PostgreSQL test.  The claim is about ``rebuild``, which is a pure
#  function, and running it against a database would prove the same thing more
#  slowly while making the failure harder to read.  The durable path is covered
#  by the acceptance suite, which calls the same ``rebuild`` with the
#  solicitations the store resolved.
SATURDAY_PRESENCE = 18


def _case() -> RaviCase:
    return ravi.ravi("ALPHA-Q12", "CASE-Q12", attested=True)


def _presence(case: RaviCase) -> Attestation:
    entry = case.entries[SATURDAY_PRESENCE]
    assert isinstance(entry, Attestation)
    return entry


def _request(case: RaviCase, *, permitting: tuple[str, ...]) -> EvidenceRequest:
    """A request naming the Saturday presence proposition, permitting these classes."""
    receipt = _presence(case).receipt
    return EvidenceRequest(
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        #  Any revision digest: the rebuild-time clause reads the targets, and
        #  binding a request to the revision it was raised against is the
        #  planner's job and the admission path's, not this clause's.
        revision_semantic_digest=receipt.payload.predicate_schema_digest,
        targets=(
            EvidenceTarget(
                proposition=receipt.payload.proposition,
                acquisition_class=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=permitting,
            ),
        ),
    )


def _cited(case: RaviCase, request: EvidenceRequest | None) -> RaviCase:
    """The case with its presence receipt citing this request, re-signed."""
    if request is None:
        return case
    presence = _presence(case)
    repointed = Attestation(
        A.sign_receipt(
            replace(
                presence.receipt,
                payload=replace(presence.receipt.payload, request_id=request.digest()),
            )
        )
    )
    entries = tuple(
        repointed if index == SATURDAY_PRESENCE else entry
        for index, entry in enumerate(case.entries)
    )
    return replace(case, entries=entries)


def _bundle(case: RaviCase) -> LoadedBundle:
    resolved = ravi.registry().resolve(case.policy_id, case.as_of)
    assert isinstance(resolved, Ok), resolved
    loaded = ravi.registry().load_by_digest(resolved.value)
    assert isinstance(loaded, Ok), loaded
    return loaded.value


def _rebuilt(case: RaviCase, solicitations: tuple[EvidenceRequest, ...]) -> object:
    bundle = _bundle(case)
    prefix = transcript_prefix(case.tenant_id, case.case_id, case.entries)
    inputs = RebuildInputs(
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        construction_digest=case.construction.digest(),
        transcript_prefix_digest=prefix.digest(),
        bundle_manifest_digest=bundle.digest(),
        as_of=case.as_of,
        mode=case.mode,
        authorization_context_digest=case.authorization_context.digest(),
    )
    return rebuild(
        inputs,
        case.construction,
        case.entries,
        bundle,
        case.authorization_context,
        case.authority_snapshot,
        case.revocation_snapshot,
        solicitations,
    )


def _established(revision: object) -> set[str]:
    return {str(fact.ref) for fact in revision.established}  # type: ignore[attr-defined]


def _presence_ref(case: RaviCase) -> str:
    return str(_presence(case).receipt.payload.proposition)


def _non_effect_reasons(revision: object, subject: str) -> set[str]:
    return {
        item.reason
        for item in revision.non_effects  # type: ignore[attr-defined]
        if item.subject == subject
    }


#  ---- A: a properly solicited, authorized receipt stays effective -----------


def test_a_properly_solicited_receipt_remains_consequential() -> None:
    """Attack A. The narrowing is a control, not a wall.

    A request that names this proposition and permits the class the source
    holds leaves the receipt exactly as effective as it was.  Without this the
    tests below would pass with the clause implemented as "refuse everything".
    """
    case = _case()
    permitted = _presence(case).receipt.payload.source_class
    request = _request(case, permitting=(permitted,))
    solicited = _cited(case, request)

    built = _rebuilt(solicited, (request,))
    assert isinstance(built, Ok), built
    assert _presence_ref(solicited) in _established(built.value)


#  ---- B: a receipt the request did not permit gains nothing ----------------


def test_Q12_TARGET_IS_REESTABLISHED_DURING_REBUILD() -> None:
    """The ratified regression. Attack B.

    The receipt is signed for real, its key holds a grant, the bundle permits
    its class for the predicate, it is inside its validity window, it is not
    revoked, and it is a durable member of the transcript.  Every clause but
    one passes -- and the request it cites narrowed the answerers to a class it
    is not.

    So the *only* thing between this receipt and an established fact is whether
    rebuild re-establishes the target condition.  It must, and the receipt must
    become a recorded non-effect rather than a fact.
    """
    case = _case()
    request = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    solicited = _cited(case, request)

    built = _rebuilt(solicited, (request,))
    assert isinstance(built, Ok), built

    ref = _presence_ref(solicited)
    assert ref not in _established(built.value), (
        "durable transcript membership made an unsolicitable receipt consequential"
    )
    #  Refused *by name*, and by the name the ratified contract gives this
    #  clause.  A silent absence would be indistinguishable from a receipt that
    #  was never delivered, and the record has to say that it arrived and was
    #  refused.
    assert "SourceClassNotPermittedForPredicate" in _non_effect_reasons(built.value, ref)


def test_the_same_receipt_is_consequential_when_the_request_permits_it() -> None:
    """B's control. The refusal above is the request's doing and nothing else.

    Identical case, identical receipt, identical everything -- one field of one
    target differs.  A regression whose refusal came from an unrelated defect
    would fail here too.
    """
    case = _case()
    permitted = _presence(case).receipt.payload.source_class
    narrow = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    wide = _request(case, permitting=(permitted,))

    refused = _rebuilt(_cited(case, narrow), (narrow,))
    admitted = _rebuilt(_cited(case, wide), (wide,))
    assert isinstance(refused, Ok) and isinstance(admitted, Ok)
    assert _presence_ref(case) not in _established(refused.value)
    assert _presence_ref(case) in _established(admitted.value)


#  ---- C: volunteered evidence follows the ratified semantics ---------------


def test_volunteered_evidence_is_not_refused_by_a_blanket_rule() -> None:
    """Attack C, and the ratified answer rather than the cautious one.

    The clause is "*where* the payload cites a request_id, also in that
    target's permitted classes".  A citation that names no request this case
    issued has no target, so the clause is vacuous -- and the receipt is judged
    by the bundle's permitted classes and by Q-12(b) through (f), which is what
    volunteered evidence has always meant here.

    Refusing it instead would be inventing a rule the contract does not state,
    and it would retroactively strip effect from evidence already admitted:
    every one of the worked fixtures cites an identifier no request resolves,
    so a blanket refusal would empty the Ravi case.
    """
    case = _case()
    built = _rebuilt(case, ())
    assert isinstance(built, Ok), built
    assert _presence_ref(case) in _established(built.value)


def test_an_unresolvable_citation_is_volunteered_rather_than_narrowed() -> None:
    """C, sharpened: the request exists but this receipt does not cite it.

    A case can hold both a request and a receipt that answers something else.
    The request is present in the view and still narrows nothing, because
    narrowing is per citation and per proposition rather than per case.
    """
    case = _case()
    unrelated = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    #  The receipt keeps its original citation, which resolves to nothing.
    built = _rebuilt(case, (unrelated,))
    assert isinstance(built, Ok), built
    assert _presence_ref(case) in _established(built.value)


#  ---- D: restart and replay produce identical semantics --------------------


def test_replaying_the_same_inputs_produces_the_same_revision() -> None:
    """Attack D. The clause moved no determinism.

    Two rebuilds of one case over one solicitation set, compared as octets.
    A clause that consulted anything mutable -- a clock, an outstanding set, a
    dictionary whose iteration order varied -- would show up here.
    """
    case = _case()
    request = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    solicited = _cited(case, request)

    first = _rebuilt(solicited, (request,))
    second = _rebuilt(solicited, (request,))
    assert isinstance(first, Ok) and isinstance(second, Ok)
    assert first.value.digest() == second.value.digest()


def test_the_order_the_solicitations_arrive_in_decides_nothing() -> None:
    """D, continued. Two requests, both orders, one answer.

    The view is keyed by digest, so order cannot matter -- which is exactly the
    kind of claim that is true until someone replaces a dict with a scan.
    """
    case = _case()
    narrow = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    other = EvidenceRequest(
        tenant_id=case.tenant_id,
        case_id=case.case_id,
        revision_semantic_digest=narrow.revision_semantic_digest,
        targets=(
            EvidenceTarget(
                proposition=case.construction.declared_instances[0],
                acquisition_class=AcquisitionClass.ATTESTABLE,
                permitted_source_classes=("ANYTHING_AT_ALL",),
            ),
        ),
    )
    solicited = _cited(case, narrow)

    forwards = _rebuilt(solicited, (narrow, other))
    backwards = _rebuilt(solicited, (other, narrow))
    assert isinstance(forwards, Ok) and isinstance(backwards, Ok)
    assert forwards.value.digest() == backwards.value.digest()


#  ---- E: a borrowed or tampered request relationship fails closed ----------


def test_a_receipt_answering_another_cases_request_is_refused_at_rebuild() -> None:
    """Attack E. A borrowed solicitation fails closed rather than laundering.

    The subtle part is why this is a *refusal* and not merely "the borrowed
    request is ignored".  Ignoring it would make a borrowed citation
    indistinguishable from an unresolvable one -- and an unresolvable citation
    means volunteered, which is an acceptance.  So an entry that reached the
    transcript some other way would gain effect on a condition the admission
    path refuses outright, and the borrowed identifier would have laundered
    itself into "no identifier at all".

    Refused in the permissive direction too, which is the dangerous one: the
    borrowed request here *permits* this receipt's class, so a rebuild that
    honoured it would be letting one case's solicitation admit evidence into
    another.
    """
    case = _case()
    borrowed = replace(
        _request(case, permitting=(_presence(case).receipt.payload.source_class,)),
        case_id=f"{case.case_id}-somebody-else",
    )
    solicited = _cited(case, borrowed)

    built = _rebuilt(solicited, (borrowed,))
    assert isinstance(built, Ok), built
    ref = _presence_ref(solicited)
    assert ref not in _established(built.value)
    #  Named as the borrowed solicitation it is, not as a class refusal.
    #  Nothing about this key or this class is wrong, and an operator reading
    #  the record has to be able to see which of the two happened.
    assert "RequestIssuedByAnotherCase" in _non_effect_reasons(built.value, ref)


def test_a_request_from_another_tenant_is_refused_the_same_way() -> None:
    """E, on the tenant axis. One tenant's solicitation does not reach another."""
    case = _case()
    foreign = replace(
        _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",)),
        tenant_id=f"{case.tenant_id}-BETA",
    )
    solicited = _cited(case, foreign)

    built = _rebuilt(solicited, (foreign,))
    assert isinstance(built, Ok), built
    ref = _presence_ref(solicited)
    assert ref not in _established(built.value)
    assert "RequestIssuedByAnotherCase" in _non_effect_reasons(built.value, ref)


def test_a_borrowed_citation_is_not_the_same_finding_as_a_forbidden_class() -> None:
    """Two refusals, two reasons, and the record distinguishes them.

    A single opaque "not admissible" would make "the source class was wrong"
    and "the request belonged to another case" the same event in every log,
    and they have different fixes.
    """
    case = _case()
    narrow = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    borrowed = replace(
        _request(case, permitting=(_presence(case).receipt.payload.source_class,)),
        case_id=f"{case.case_id}-somebody-else",
    )
    by_class = _rebuilt(_cited(case, narrow), (narrow,))
    by_borrowing = _rebuilt(_cited(case, borrowed), (borrowed,))
    assert isinstance(by_class, Ok) and isinstance(by_borrowing, Ok)

    ref = _presence_ref(case)
    assert "SourceClassNotPermittedForPredicate" in _non_effect_reasons(by_class.value, ref)
    assert "RequestIssuedByAnotherCase" in _non_effect_reasons(by_borrowing.value, ref)


def test_a_tampered_request_cannot_be_supplied_under_the_cited_digest() -> None:
    """E, on the content axis. The digest binds, so substitution is not a thing.

    A caller hands in a request whose targets have been widened, hoping it will
    be used for a citation that names the *narrow* one.  The view keys by the
    request's own recomputed digest, so the widened one lands under a different
    key, the narrow citation resolves to nothing there, and the widened targets
    are never read for this receipt.
    """
    case = _case()
    narrow = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    solicited = _cited(case, narrow)

    widened = replace(
        narrow,
        targets=(
            replace(
                narrow.targets[0],
                permitted_source_classes=(_presence(case).receipt.payload.source_class,),
            ),
        ),
    )
    assert widened.digest() != narrow.digest()

    #  Only the tampered version is supplied, under a caller who would like it
    #  to answer for the cited one.
    built = _rebuilt(solicited, (widened,))
    assert isinstance(built, Ok), built
    #  Volunteered -- the tampering bought nothing, because it could not be
    #  filed under the digest the receipt cites.
    assert _presence_ref(case) in _established(built.value)

    #  And with the genuine narrow request present, the refusal returns.
    refused = _rebuilt(solicited, (narrow,))
    assert isinstance(refused, Ok), refused
    assert _presence_ref(case) not in _established(refused.value)


#  ---- the fact is a fact, not merely present -------------------------------


def test_a_narrowed_receipt_leaves_no_attested_provenance_behind() -> None:
    """Refused means refused: no fact, and no fact citing this receipt.

    Checking the reference is absent from ``established`` would still pass if
    the value arrived under a different reference, or if the constraint channel
    carried it instead.  This checks that nothing anywhere in the revision is
    attested by this receipt's digest.
    """
    case = _case()
    request = _request(case, permitting=("SOMEBODY_ELSE_ENTIRELY",))
    solicited = _cited(case, request)
    receipt_digest = _presence(solicited).receipt.digest()

    built = _rebuilt(solicited, (request,))
    assert isinstance(built, Ok), built
    for fact in built.value.established:
        assert not (
            isinstance(fact.justification, AttestedBy)
            and fact.justification.receipt_digest == receipt_digest
        ), fact
    for constraint in built.value.constraints:
        assert receipt_digest.hex[:12] not in constraint.label, constraint
