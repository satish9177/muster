"""Check Q-12 under attack: a valid signature is not an authorization.

Every test here starts from a receipt that is **structurally perfect**.  The
relation is well formed, the value is in domain, the sort matches, the tenant
and the case are right, the schema pin is right, the key is real and unrevoked.
On the durable path its signature verifies.  What varies is one clause of
Q-12, and the expected result is a refusal naming *that* clause.

That construction is the whole point.  A test that also broke something else
would pass under an implementation that had no authority check at all, and
would go on passing while the property it was named for quietly did not hold.
So each test below asserts the *specific* failure, and the two ratified
adversarial requirements assert more than that: they say which clauses
**passed**, because "the receipt was refused" is not the claim -- "a shared
source class is not a shared authority" is.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest

from muster.core.authority.check import (
    AuthorityError,
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
from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval
from tests.support import authority as A

PRESENT = SymbolRef("present_on_site", ("RAVI", "SAT"))
DURATION = SymbolRef("on_site_duration", ("RAVI", "SAT"))
GOODS_RECEIPT = SymbolRef("accepted_quantity", ("PO-4471",))

SITE_PREDICATES = ("on_site_duration", "present_on_site")

#  What the pinned bundle permits for each predicate, as ``PredicateInfo`` would
#  carry it.  Separate from the grants below, because clause (a) reads the
#  bundle and clauses (b) to (f) read the registry, and a test that conflated
#  them could not tell which one refused.
SITE_CLASSES = frozenset({A.SOURCE_SITE_ACCESS})
GOODS_CLASSES = frozenset({A.SOURCE_GOODS_RECEIPT})


def _site_grant(**changes: Any) -> AuthorityGrant:
    """The badge reader's grant, with one field varied.

    ``Any`` rather than a precise mapping because the values are genuinely
    heterogeneous -- a tuple of atoms, an interval, an integer -- and the point
    of the helper is that a test names the one field it is attacking.
    """
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


def _healthy() -> tuple[AuthorityRegistrySnapshot, SourceClaim]:
    """A snapshot that authorizes the site key, and the claim it authorizes."""
    return A.snapshot(_site_grant()), A.claim(PRESENT)


@dataclass(frozen=True, slots=True)
class Pinned:
    """The pinned state a claim is judged against, as one value.

    A parameter object rather than nine keyword arguments, because the point of
    every test below is *one* of these differing from the control -- and a call
    site that named nine things would bury which one.
    """

    permitted: frozenset[str] = SITE_CLASSES
    arg_kinds: tuple[str, ...] = ("WORKER", "DAY")
    scope_kinds: tuple[str, ...] = ("SITE",)
    coordinates: tuple[ResourceScope, ...] = A.CASE_COORDINATES
    revoked: tuple[str, ...] = ()
    as_of: int = A.NOW
    tenant_id: str = A.TENANT
    policy_version: int = A.POLICY_VERSION


def _check(
    claim: SourceClaim,
    snapshot: AuthorityRegistrySnapshot,
    **changes: Any,
) -> Result[AuthorityGrant, AuthorityError]:
    pinned = replace(Pinned(), **changes)
    permitted = pinned.permitted
    arg_kinds = pinned.arg_kinds
    scope_kinds = pinned.scope_kinds
    coordinates = pinned.coordinates
    revoked = pinned.revoked
    as_of = pinned.as_of
    tenant_id = pinned.tenant_id
    policy_version = pinned.policy_version
    view = A.view(
        snapshot,
        A.revocation(*revoked, tenant_id=tenant_id),
        tenant_id=tenant_id,
        coordinates=coordinates,
        as_of=as_of,
        policy_version=policy_version,
    )
    return check_authority(
        claim,
        permitted,
        required_coordinates(claim.proposition, arg_kinds, scope_kinds, coordinates),
        view,
    )


def _refused(outcome: Result[AuthorityGrant, AuthorityError]) -> AuthorityFailure:
    assert isinstance(outcome, Err), outcome
    return outcome.error.failure


#  ---- the control -----------------------------------------------------------


def test_the_unmodified_claim_is_authorized() -> None:
    """Without this every refusal below could be refusing for its own reasons."""
    snapshot, claim = _healthy()
    outcome = _check(claim, snapshot)
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.key_ref == A.SITE_A_KEY


#  ---- the two ratified adversarial requirements -----------------------------


def test_WORKER_KEY_CANNOT_ATTEST_GOODS_RECEIPT() -> None:
    """A real, valid, unrevoked worker key declaring a goods-receipt class.

    This is the exact payload that passed every executed check before Q-12
    existed: the signature verifies, the tenant matches, the key is live, the
    relation is well formed, and the bundle permits ``GOODS_RECEIPT_SYSTEM``
    for this predicate -- so clause (a) passes.  What does not exist is a grant
    binding *this key* to that class, and clause (b) is where it stops.
    """
    snapshot = A.snapshot(
        _site_grant(),
        #  The worker key is in the snapshot, holding a real grant of its own,
        #  so this is not "an unknown key".  It simply is not a goods-receipt
        #  system, and no amount of declaring makes it one.
        A.grant(
            key_ref=A.WORKER_KEY,
            principal_id="RAVI",
            source_class="WORKER_SELF_REPORT",
            predicates=("present_on_site",),
            scope=(ResourceScope("SITE", A.SITE_A),),
        ),
    )
    claim = A.claim(GOODS_RECEIPT, key_ref=A.WORKER_KEY, source_class=A.SOURCE_GOODS_RECEIPT)
    outcome = _check(
        claim,
        snapshot,
        permitted=GOODS_CLASSES,
        arg_kinds=("PURCHASE_ORDER",),
        scope_kinds=("PURCHASE_ORDER",),
        coordinates=(ResourceScope("PURCHASE_ORDER", "PO-4471"),),
    )
    assert _refused(outcome) is AuthorityFailure.UNAUTHORIZED_SOURCE_CLASS_FOR_KEY


def test_SITE_A_KEY_CANNOT_ATTEST_SITE_B() -> None:
    """Clause (d), and *only* (d) -- which is the point of the requirement.

    Key ``S_A`` holds a valid, in-validity grant: right tenant, right source
    class, right predicate, unrevoked, right policy version.  Every clause but
    one passes.  The case is about ``SITE_B``, and a shared ``source_class`` is
    not a shared authority.

    The other clauses are asserted to pass rather than assumed to, by running
    the same claim against the same snapshot with only the case's site changed:
    if that succeeds and this fails, the difference is the site and nothing
    else.
    """
    snapshot = A.snapshot(_site_grant())
    claim = A.claim(PRESENT)

    at_site_a = _check(claim, snapshot, coordinates=(ResourceScope("SITE", A.SITE_A),))
    assert isinstance(at_site_a, Ok), at_site_a

    at_site_b = _check(claim, snapshot, coordinates=(ResourceScope("SITE", A.SITE_B),))
    assert _refused(at_site_b) is AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED


#  ---- the named milestone-E regressions -------------------------------------


def test_VALID_SIGNATURE_WITHOUT_AUTHORITY_REJECTED() -> None:
    """A key the registry has never heard of, refused on authority alone.

    Nothing here is about cryptography: this function never sees a signature.
    That separation *is* the milestone -- authenticity is established
    elsewhere, and holds perfectly well for a key that may say nothing at all.
    """
    snapshot, _ = _healthy()
    stranger = A.claim(PRESENT, key_ref="key-nobody-1")
    assert _refused(_check(stranger, snapshot)) is (
        AuthorityFailure.UNAUTHORIZED_SOURCE_CLASS_FOR_KEY
    )


def test_WRONG_TENANT_AUTHORITY_REJECTED() -> None:
    """Tenant A's snapshot cannot decide tenant B's case.

    The chain is four-way -- grant, snapshot, revision, payload -- and each
    break is checked separately, because a single comparison against "the"
    tenant would silently accept whichever one it happened to read.
    """
    snapshot, _ = _healthy()

    #  The receipt claims another tenant.
    foreign_payload = A.claim(PRESENT, tenant_id="BETA")
    assert _refused(_check(foreign_payload, snapshot)) is AuthorityFailure.CROSS_TENANT_AUTHORITY

    #  The revision is another tenant's; the snapshot and payload agree with
    #  each other and not with it.
    other = A.snapshot(_site_grant(tenant_id="BETA"), tenant_id="BETA")
    assert (
        _refused(_check(A.claim(PRESENT, tenant_id="BETA"), other, tenant_id=A.TENANT))
        is AuthorityFailure.CROSS_TENANT_AUTHORITY
    )


def test_CROSS_TENANT_REVOCATION_STATE_REJECTED() -> None:
    """And the revocation snapshot is tenant state too.

    An untenanted revocation list would be equally valid under every tenant,
    which is the borrowing this clause exists to refuse: "somebody revoked this
    key" is not a fact until it says who.
    """
    snapshot, _ = _healthy()
    claim = A.claim(PRESENT)
    view = A.view(
        snapshot,
        A.revocation(tenant_id="BETA"),
        tenant_id=A.TENANT,
    )
    outcome = check_authority(
        claim,
        SITE_CLASSES,
        required_coordinates(PRESENT, ("WORKER", "DAY"), ("SITE",), A.CASE_COORDINATES),
        view,
    )
    assert _refused(outcome) is AuthorityFailure.CROSS_TENANT_AUTHORITY


def test_WRONG_SOURCE_CLASS_REJECTED() -> None:
    """The class is signer-supplied and selects a grant; it never creates one."""
    snapshot, _ = _healthy()
    claiming_payroll = A.claim(PRESENT, source_class=A.SOURCE_PAYROLL)
    #  Clause (a) refuses it first: the pinned bundle does not permit payroll
    #  for this predicate, whatever the registry might say.
    assert _refused(_check(claiming_payroll, snapshot)) is (
        AuthorityFailure.SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE
    )
    #  And with a bundle that *does* permit it, clause (b) refuses it instead:
    #  the site key holds no payroll grant.  Two different refusals for two
    #  different reasons, which is what makes them worth distinguishing.
    assert (
        _refused(_check(claiming_payroll, snapshot, permitted=frozenset({A.SOURCE_PAYROLL})))
        is AuthorityFailure.UNAUTHORIZED_SOURCE_CLASS_FOR_KEY
    )


def test_PREDICATE_NOT_GRANTED_REJECTED() -> None:
    """Right key, right class, right site, wrong proposition."""
    narrow = A.snapshot(_site_grant(predicates=("present_on_site",)))
    assert _refused(_check(A.claim(DURATION), narrow)) is (
        AuthorityFailure.PREDICATE_NOT_AUTHORIZED_FOR_KEY
    )
    #  And the predicate it *does* hold still works, so the grant is narrow
    #  rather than broken.
    assert isinstance(_check(A.claim(PRESENT), narrow), Ok)


def test_RESOURCE_SCOPE_PREFIX_ATTACK_REJECTED() -> None:
    """``site-1`` is a prefix of ``site-10`` and reaches none of it.

    The trap this is named after: a containment rule would hand the holder of
    a grant over the first an authority over the second that nobody wrote down,
    and the mistake stays invisible until a site is named with a digit added.
    Matching is set membership over the whole ``(kind, value)`` pair, and this
    is the test that says so in the shape the mistake takes.
    """
    snapshot = A.snapshot(_site_grant(scope=(ResourceScope("SITE", "site-1"),)))
    claim = A.claim(PRESENT)

    exact = _check(claim, snapshot, coordinates=(ResourceScope("SITE", "site-1"),))
    assert isinstance(exact, Ok), exact

    for neighbour in ("site-10", "site-1x", "site-", "SITE-1", "site-1 "):
        outcome = _check(claim, snapshot, coordinates=(ResourceScope("SITE", neighbour),))
        assert _refused(outcome) is AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED, neighbour

    #  And in the other direction: a grant over the longer name does not reach
    #  the shorter one either.
    longer = A.snapshot(_site_grant(scope=(ResourceScope("SITE", "site-10"),)))
    assert (
        _refused(_check(claim, longer, coordinates=(ResourceScope("SITE", "site-1"),)))
        is AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED
    )


def test_A_KIND_MISMATCH_IS_NOT_A_VALUE_MATCH() -> None:
    """The pair is compared, not the value.

    A grant over ``(COST_CENTRE, SITE-A)`` must not reach a case whose site is
    ``SITE-A``.  Comparing values alone would make every coordinate kind one
    namespace, which is how an authority over a cost centre becomes an
    authority over a site with the same identifier.
    """
    snapshot = A.snapshot(_site_grant(scope=(ResourceScope("COST_CENTRE", A.SITE_A),)))
    assert _refused(_check(A.claim(PRESENT), snapshot)) is (
        AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED
    )


def test_RESOURCE_SCOPE_UNDETERMINED_REJECTED() -> None:
    """A coordinate nobody supplied is a refusal, never "any".

    The subtlest failure mode in the whole check: if the required set is empty,
    the subset test that decides clause (d) succeeds vacuously and every grant
    reaches every resource.  So the empty set is refused before the test runs.
    """
    snapshot, claim = _healthy()
    #  The predicate is scoped by SITE, its arguments carry no site, and the
    #  case declares none.  There is nothing for a grant to have been written
    #  about.
    outcome = _check(claim, snapshot, coordinates=())
    assert _refused(outcome) is AuthorityFailure.RESOURCE_SCOPE_UNDETERMINED

    #  And a scope kind the case does not carry, alongside one it does: a
    #  partially resolvable set is still a refusal, not a partial check.
    outcome = _check(claim, snapshot, scope_kinds=("SITE", "COST_CENTRE"))
    assert _refused(outcome) is AuthorityFailure.RESOURCE_SCOPE_UNDETERMINED


def test_NOT_YET_VALID_GRANT_REJECTED() -> None:
    """Before the window opens. ``[start, end)``, judged at the revision's as_of."""
    window = HalfOpenInterval(A.NOW + 1, A.NOW + 1_000)
    snapshot = A.snapshot(_site_grant(validity=window))
    assert _refused(_check(A.claim(PRESENT), snapshot)) is (
        AuthorityFailure.AUTHORITY_NOT_YET_VALID
    )


def test_EXPIRED_GRANT_REJECTED() -> None:
    """After it closes."""
    window = HalfOpenInterval(A.NOW - 1_000, A.NOW)
    snapshot = A.snapshot(_site_grant(validity=window))
    assert _refused(_check(A.claim(PRESENT), snapshot)) is AuthorityFailure.AUTHORITY_EXPIRED


def test_the_validity_interval_is_half_open_at_both_ends() -> None:
    """Admitted at the start instant and at the microsecond before the end.

    Four points rather than two: the boundaries are where an off-by-one lives,
    and "expired" and "not yet valid" are the two ways to get one wrong.
    """
    start, end = A.NOW - 10, A.NOW + 10
    snapshot = A.snapshot(_site_grant(validity=HalfOpenInterval(start, end)))
    claim = A.claim(PRESENT)

    assert _refused(_check(claim, snapshot, as_of=start - 1)) is (
        AuthorityFailure.AUTHORITY_NOT_YET_VALID
    )
    assert isinstance(_check(claim, snapshot, as_of=start), Ok)
    assert isinstance(_check(claim, snapshot, as_of=end - 1), Ok)
    assert _refused(_check(claim, snapshot, as_of=end)) is AuthorityFailure.AUTHORITY_EXPIRED


def test_REVOKED_GRANT_REJECTED() -> None:
    """The signature still verifies. Revocation withdraws authority, not mathematics.

    Which is exactly why this clause is here and not in the verifier: a revoked
    key's output is as authentic as it ever was, and that is not the question.
    """
    snapshot, claim = _healthy()
    assert isinstance(_check(claim, snapshot), Ok)
    assert _refused(_check(claim, snapshot, revoked=(A.SITE_A_KEY,))) is (
        AuthorityFailure.KEY_REVOKED
    )


def test_AUTHORIZATION_POLICY_VERSION_MISMATCH_REJECTED() -> None:
    """Old grant plus new policy is not accidental authority.

    Four values must agree -- the grant's, the snapshot's, the context's and
    the receipt's -- and each disagreement is checked separately, because a
    version that is "mapped" silently is a version that means whatever the
    reader needed it to.
    """
    snapshot, _ = _healthy()

    #  The receipt claims a version the case did not pin.
    assert _refused(_check(A.claim(PRESENT, policy_version=2), snapshot)) is (
        AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH
    )
    #  The case pins a version the snapshot was not published under.
    assert (
        _refused(_check(A.claim(PRESENT, policy_version=2), snapshot, policy_version=2))
        is AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH
    )
    #  And a grant issued under an older version than its own snapshot.
    stale = A.snapshot(_site_grant(policy_version=1), policy_version=2)
    assert (
        _refused(_check(A.claim(PRESENT, policy_version=2), stale, policy_version=2))
        is AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH
    )


def test_AMBIGUOUS_AUTHORITY_GRANT_REJECTED() -> None:
    """Two grants on one (key, class) fail closed rather than being arbitrated.

    Unrepresentable through the constructor, which is where a publisher meets
    it.  Reachable only by going around the constructor the way a store or a
    forged row would -- so the *lookup* refuses it too, because octets read
    back from a store went through no constructor an adversary could not also
    have gone around.
    """
    first = _site_grant(predicates=("present_on_site",))
    second = _site_grant(predicates=SITE_PREDICATES, scope=(ResourceScope("SITE", A.SITE_B),))
    with pytest.raises(InvariantViolation, match="ambiguity"):
        A.snapshot(first, second)

    smuggled = object.__new__(AuthorityRegistrySnapshot)
    object.__setattr__(smuggled, "registry_id", A.REGISTRY_ID)
    object.__setattr__(smuggled, "tenant_id", A.TENANT)
    object.__setattr__(smuggled, "authorization_policy_version", A.POLICY_VERSION)
    object.__setattr__(smuggled, "grants", canonical_grants((first, second)))
    object.__setattr__(smuggled, "published_at", A.FOREVER.start)
    assert _refused(_check(A.claim(PRESENT), smuggled)) is (
        AuthorityFailure.AMBIGUOUS_AUTHORITY_GRANT
    )


def test_ONE_KEY_BELONGS_TO_ONE_PRINCIPAL() -> None:
    """A key claimed by two institutions is a malformed snapshot.

    Without it, one key could hold a site grant as ``SITE-A`` and a payroll
    grant as ``EMPLOYER-1``, and "which institution signed this" would have no
    answer -- while every individual clause of Q-12 still passed.
    """
    with pytest.raises(InvariantViolation, match="claimed by two principals"):
        A.snapshot(
            _site_grant(),
            _site_grant(
                source_class=A.SOURCE_PAYROLL,
                principal_id=A.EMPLOYER,
                predicates=("daily_rate",),
                scope=(ResourceScope("EMPLOYER", A.EMPLOYER),),
            ),
        )


def test_a_grant_cannot_be_written_over_nothing() -> None:
    """Both enumerated fields have a floor of one member.

    "No predicates" and "no resources" are the two ways to write a grant that a
    permissive reader could take for "everything", so neither is representable
    -- refused by the constructor rather than checked for at every use.
    """
    with pytest.raises(InvariantViolation, match="permitting no predicate"):
        _site_grant(predicates=())
    with pytest.raises(InvariantViolation, match="over no resource"):
        _site_grant(scope=())


def test_a_wildcard_coordinate_is_unrepresentable() -> None:
    """Not rejected at match time -- refused at construction.

    ``scope_value`` is an ATOM, so a wildcard *spelling* is representable even
    though a wildcard *meaning* is not.  Refusing the spellings removes the
    reading in which a publisher believed one worked: an authority field that
    silently means "nothing" is as dangerous as one that silently means
    "everything".
    """
    for spelling in ("*", "ANY", "ALL", "ALL_SITES", "any_predicate"):
        with pytest.raises(InvariantViolation, match="never a wildcard"):
            ResourceScope("SITE", spelling)
        with pytest.raises(InvariantViolation, match="never a wildcard"):
            ResourceScope(spelling, A.SITE_A)


def test_the_predicate_argument_supplies_its_own_coordinate() -> None:
    """The procurement shape, and the one that proves the layer is generic.

    ``accepted_quantity(PO-4471)`` carries its purchase order in an argument,
    so the coordinate comes from the proposition rather than from the case --
    and a grant over a different order does not reach it.  No workforce concept
    appears anywhere in this test, and no production code changed to make it
    possible.
    """
    holder = A.snapshot(
        A.grant(
            key_ref="key-goods-receipt-1",
            principal_id="WH-1",
            source_class=A.SOURCE_GOODS_RECEIPT,
            predicates=("accepted_quantity",),
            scope=(ResourceScope("PURCHASE_ORDER", "PO-4471"),),
        )
    )
    claim = A.claim(
        GOODS_RECEIPT, key_ref="key-goods-receipt-1", source_class=A.SOURCE_GOODS_RECEIPT
    )
    mine = _check(
        claim,
        holder,
        permitted=GOODS_CLASSES,
        arg_kinds=("PURCHASE_ORDER",),
        scope_kinds=("PURCHASE_ORDER",),
        coordinates=(),
    )
    assert isinstance(mine, Ok), mine

    theirs = A.claim(
        SymbolRef("accepted_quantity", ("PO-9999",)),
        key_ref="key-goods-receipt-1",
        source_class=A.SOURCE_GOODS_RECEIPT,
    )
    assert (
        _refused(
            _check(
                theirs,
                holder,
                permitted=GOODS_CLASSES,
                arg_kinds=("PURCHASE_ORDER",),
                scope_kinds=("PURCHASE_ORDER",),
                coordinates=(),
            )
        )
        is AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED
    )


def test_a_refusal_never_names_a_grant_the_claimant_does_not_hold() -> None:
    """Typed reason inside, and nothing about the registry on the way out.

    A rejection that named the grants a key *does* hold would turn every
    refused attestation into a query against the registry -- ask for something
    you cannot have, and be told what you can.  Details are built from what the
    claimant already supplied and from the coordinates its own proposition
    ranges over, and this checks the negative directly.
    """
    snapshot = A.snapshot(
        _site_grant(),
        A.grant(
            key_ref=A.PAYROLL_KEY,
            principal_id=A.EMPLOYER,
            source_class=A.SOURCE_PAYROLL,
            predicates=("daily_rate", "scheduled"),
            scope=(ResourceScope("EMPLOYER", A.EMPLOYER),),
        ),
    )
    outcome = _check(A.claim(PRESENT, key_ref="key-nobody-1"), snapshot)
    assert isinstance(outcome, Err)
    detail = outcome.error.detail
    for secret in (A.PAYROLL_KEY, A.EMPLOYER, "daily_rate", "scheduled", A.SITE_A_KEY):
        assert secret not in detail, secret
