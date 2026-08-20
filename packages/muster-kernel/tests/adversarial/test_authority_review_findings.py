"""Regressions for the defects the milestone-E reviews found.

One file, because what these have in common is how they were found rather than
what they are about: each is a hole that the suite as written would not have
noticed, and each now has a test that fails if the fix is reverted.

Two of them -- ``PRINCIPAL_MISMATCH`` and ``CROSS_TENANT_AUTHORITY`` -- are
clauses of Q-12 that the *constructor* makes unreachable.  That is the right
shape for the constructor, and it left the runtime clause untested and
therefore deletable.  Both are exercised here by smuggling a malformed snapshot
past ``__post_init__`` with ``object.__new__``, which is what a forged row or a
reader that skipped validation would produce.  A clause that is only reachable
by an adversary still has to work, and a clause no test reaches is a clause
whose deletion nothing reports.
"""

from __future__ import annotations

from typing import Any

import pytest

from muster.core.authority.check import (
    AuthorityFailure,
    SourceClaim,
    check_authority,
    required_coordinates,
)
from muster.core.authority.grants import (
    AuthorityGrant,
    AuthorityRegistrySnapshot,
    canonical_grants,
)
from muster.core.authority.scope import WILDCARD_SPELLINGS, ResourceScope
from muster.core.results import Err, InvariantViolation, Ok
from muster.core.values.symbols import SymbolRef
from tests.support import authority as A

PRESENT = SymbolRef("present_on_site", ("RAVI", "SAT"))
SITE_PREDICATES = ("on_site_duration", "present_on_site")


def _grant(**changes: Any) -> AuthorityGrant:
    return A.grant(
        **{
            "key_ref": A.SITE_A_KEY,
            "principal_id": A.SITE_A,
            "source_class": A.SOURCE_SITE_ACCESS,
            "predicates": SITE_PREDICATES,
            "scope": (ResourceScope("SITE", A.SITE_A),),
            **changes,
        }
    )


def _smuggled(*grants: AuthorityGrant, tenant_id: str = A.TENANT) -> AuthorityRegistrySnapshot:
    """A snapshot the constructor would refuse, assembled past it.

    Exactly what a corrupted row or a forged publication produces, and the only
    way to reach the clauses that exist for that case.  Using the real
    constructor would be testing the constructor, which the tests beside these
    already do.
    """
    smuggled = object.__new__(AuthorityRegistrySnapshot)
    object.__setattr__(smuggled, "registry_id", A.REGISTRY_ID)
    object.__setattr__(smuggled, "tenant_id", tenant_id)
    object.__setattr__(smuggled, "authorization_policy_version", A.POLICY_VERSION)
    object.__setattr__(smuggled, "grants", canonical_grants(grants))
    object.__setattr__(smuggled, "published_at", A.FOREVER.start)
    return smuggled


def _check(
    snapshot: AuthorityRegistrySnapshot,
    *,
    claim: SourceClaim | None = None,
    coordinates: tuple[ResourceScope, ...] = A.CASE_COORDINATES,
    scope_kinds: tuple[str, ...] = ("SITE",),
    arg_kinds: tuple[str, ...] = ("WORKER", "DAY"),
    permitted: frozenset[str] = frozenset({A.SOURCE_SITE_ACCESS}),
) -> object:
    statement = claim if claim is not None else A.claim(PRESENT)
    return check_authority(
        statement,
        permitted,
        required_coordinates(statement.proposition, arg_kinds, scope_kinds, coordinates),
        A.view(snapshot, coordinates=coordinates),
    )


#  ---- the resolver has to be total ------------------------------------------


@pytest.mark.parametrize("spelling", [*sorted(WILDCARD_SPELLINGS), ""])
def test_A_WILDCARD_ARGUMENT_IS_REFUSED_NOT_RAISED(spelling: str) -> None:
    """A proposition argument the attacker chose must not crash Q-12(d).

    ``ResourceScope`` refuses an empty or wildcard-shaped value by raising,
    which is right for a publisher assembling a grant and wrong for a value
    that came off a signed payload: that is *input*, and a refusal has to be a
    value.  Before the fix, any key whose signature verified -- including one
    holding no grant at all, because this runs before ``check_authority`` --
    could raise ``InvariantViolation`` out of the admission path, which
    promises a ``Result``.

    ``pytest.raises`` is deliberately absent: the whole point is that nothing
    raises.
    """
    proposition = SymbolRef("accepted_quantity", (spelling,))
    required = required_coordinates(proposition, ("PURCHASE_ORDER",), ("PURCHASE_ORDER",), ())
    assert required.undeterminable == frozenset({"PURCHASE_ORDER"})
    assert required.coordinates == frozenset()

    outcome = _check(
        A.snapshot(_grant()),
        claim=A.claim(proposition),
        coordinates=(),
        scope_kinds=("PURCHASE_ORDER",),
        arg_kinds=("PURCHASE_ORDER",),
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.RESOURCE_SCOPE_UNDETERMINED


def test_a_case_at_two_sites_needs_a_grant_over_both() -> None:
    """Coordinates of a repeated kind are all required, not the last one.

    A dict keyed by scope kind kept one of a case's two sites and dropped the
    other -- and the dropped one is a *requirement*, so the mistake widened
    authority rather than narrowing it, which is the only direction that
    matters.
    """
    both = (ResourceScope("SITE", A.SITE_A), ResourceScope("SITE", A.SITE_B))
    required = required_coordinates(PRESENT, ("WORKER", "DAY"), ("SITE",), both)
    assert required.coordinates == frozenset(both)

    narrow = A.snapshot(_grant())
    assert isinstance(_check(narrow, coordinates=both), Err)

    wide = A.snapshot(
        _grant(scope=(ResourceScope("SITE", A.SITE_A), ResourceScope("SITE", A.SITE_B)))
    )
    assert isinstance(_check(wide, coordinates=both), Ok)


def test_a_repeated_scope_kind_argument_needs_every_one_of_its_values() -> None:
    """The same rule on the argument side, which the docstring claimed and no test read."""
    proposition = SymbolRef("transfer_quantity", ("PO-1", "PO-2"))
    kinds = ("PURCHASE_ORDER", "PURCHASE_ORDER")
    required = required_coordinates(proposition, kinds, ("PURCHASE_ORDER",), ())
    assert required.coordinates == frozenset(
        {ResourceScope("PURCHASE_ORDER", "PO-1"), ResourceScope("PURCHASE_ORDER", "PO-2")}
    )
    assert not required.undeterminable


#  ---- clauses only an adversary reaches ------------------------------------


def test_PRINCIPAL_MISMATCH_REJECTED() -> None:
    """One key claimed by two institutions, smuggled past the constructor.

    Q-12(d)'s principal half is unreachable through the public constructor,
    because a snapshot binding one key to two principals is refused when it is
    built.  That is correct and it left the *runtime* clause untested: deleting
    it, or inverting the comparison, broke nothing.

    Here the snapshot is assembled past ``__post_init__`` -- the state a forged
    row produces -- and the clause fires.  ``resolve_authority`` would refuse
    such octets before they reached this function; this is the second line
    behind that, and second lines have to be checked too.
    """
    site = _grant()
    payroll = _grant(
        source_class=A.SOURCE_PAYROLL,
        principal_id=A.EMPLOYER,
        predicates=("daily_rate",),
        scope=(ResourceScope("EMPLOYER", A.EMPLOYER),),
    )
    with pytest.raises(InvariantViolation, match="claimed by two principals"):
        A.snapshot(site, payroll)

    smuggled = _smuggled(site, payroll)
    #  ``principal_for`` returns whichever grant sorts first; the claim below
    #  resolves the other one, so the two disagree and the clause fires.
    disagreeing = [
        grant
        for grant in smuggled.grants
        if grant.principal_id != smuggled.principal_for(A.SITE_A_KEY)
    ]
    assert disagreeing, "the smuggled snapshot must actually disagree with itself"
    target = disagreeing[0]

    #  The claim is aimed at the grant that disagrees, with the bundle half of
    #  Q-12(a) arranged to pass for that class -- otherwise the receipt is
    #  refused two clauses earlier and this test would be about clause (a).
    outcome = _check(
        smuggled,
        claim=A.claim(
            SymbolRef(target.permitted_predicates[0], ("RAVI", "SAT")),
            source_class=target.source_class,
        ),
        coordinates=A.CASE_COORDINATES,
        scope_kinds=("SITE",) if target.source_class == A.SOURCE_SITE_ACCESS else ("EMPLOYER",),
        permitted=frozenset({target.source_class}),
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.PRINCIPAL_MISMATCH


def test_CROSS_TENANT_GRANT_IN_A_SNAPSHOT_IS_REJECTED() -> None:
    """A grant scoped to another tenant, inside this tenant's snapshot.

    The admission path's binding check compares the *entry's* tenant to the
    *case's* -- both this tenant -- so it never sees a mis-scoped grant.  Q-12(c)
    was the only thing between one and an authorization, and nothing made the
    state unpublishable, so every platform "wrong tenant" test was actually
    exercising the binding check and Q-12(c) could have been deleted unnoticed.

    Now the state is refused at construction *and* the clause is exercised past
    it.
    """
    with pytest.raises(InvariantViolation, match="is scoped to"):
        A.snapshot(_grant(tenant_id="BETA"))

    smuggled = _smuggled(_grant(tenant_id="BETA"))
    outcome = _check(smuggled)
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.CROSS_TENANT_AUTHORITY


def test_the_fourth_policy_version_disagreement_is_refused() -> None:
    """Grant, snapshot and claim agree; the revision's own pin does not.

    The fourth corner of a four-way equality the test beside this one checks
    three corners of.  A version the *case* pinned that nobody else carries is
    the one an operator reaches by re-pinning a case and forgetting to
    republish.
    """
    snapshot = A.snapshot(_grant(policy_version=1), policy_version=1)
    claim = A.claim(PRESENT, policy_version=1)
    outcome = check_authority(
        claim,
        frozenset({A.SOURCE_SITE_ACCESS}),
        required_coordinates(PRESENT, ("WORKER", "DAY"), ("SITE",), A.CASE_COORDINATES),
        A.view(snapshot, policy_version=2),
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH


def test_every_authority_failure_is_reachable_by_some_test() -> None:
    """A named rejection nothing can produce is a rejection nobody has checked.

    The review found two clauses that were structurally unreachable and one
    that no test exercised.  This is the guard that would have found all three:
    it fails the moment a member of ``AuthorityFailure`` exists that no test in
    this package names.

    Grepping the test tree rather than instrumenting the check, because the
    property is about *coverage of the vocabulary*, and a member produced only
    by production code that no test asserts on is exactly the state this
    exists to refuse.
    """
    import pathlib

    tests = pathlib.Path(__file__).resolve().parent.parent
    corpus = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(tests.rglob("test_*.py"))
    )
    unreferenced = [
        member.name
        for member in AuthorityFailure
        if f"AuthorityFailure.{member.name}" not in corpus
    ]
    assert not unreferenced, f"no test names {unreferenced}"


#  ---- the residual the solicitation check leaves ---------------------------


def test_an_evidence_target_is_never_narrower_than_the_pinned_schema() -> None:
    """The invariant that makes an unresolvable ``request_id`` harmless today.

    Admission checks a receipt's source class against the ``EvidenceTarget`` of
    the request it cites -- the second half of Q-12(a) -- but only when that
    request resolves.  The identifier is inside the attacker's own payload, so
    an attacker can always make it *not* resolve, and skip that half.

    That grants nothing **only because** a target is built by copying the
    pinned schema's permitted classes verbatim, so no target is ever narrower
    than the check that always runs.  The day a producer narrows one -- a
    request only the badge reader may answer, not a supervisor -- the narrowing
    would be defeated by one field the attacker controls.

    So the invariant is asserted rather than assumed, and this test is the
    thing that fails on that day and points at ``_check_solicitation``.
    """
    from muster.application.pipeline import acquirable_targets
    from muster.core.values.classification import AcquisitionClass
    from muster.domains.workforce.bundle import workforce_bundle

    schema = workforce_bundle().predicate_schema
    attestable = tuple(
        spec for spec in schema.predicates if spec.acquisition is AcquisitionClass.ATTESTABLE
    )
    assert attestable, "the bundle must declare something attestable for this to mean anything"

    specs = {
        SymbolRef(
            spec.predicate_id, tuple(f"arg-{index}" for index in range(len(spec.arg_kinds)))
        ): spec
        for spec in attestable
    }
    targets = acquirable_targets(specs, tuple(specs))
    assert targets

    for target in targets:
        spec = specs[target.proposition]
        assert set(target.permitted_source_classes) == set(spec.permitted_source_classes), (
            f"{target.proposition} narrows the schema; ``_check_solicitation`` can be "
            f"evaded with an unresolvable request_id, so a narrower target is not a control"
        )
