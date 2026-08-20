"""Check Q-12 -- deterministic source authorization.

**Signed is not authorized.**  A signature answers "which key produced these
octets".  Q-12 answers the question that decides admissibility:

    was *this key*, as *this institutional principal*, in *this tenant*,
    holding *this source class*, permitted to assert *this predicate* over
    *this resource*, under *this authorization-policy version*, at *this
    instant*, and not revoked?

Every input except the claim itself comes from state the claimant could not
choose.  The snapshot is resolved by digest from the revision's pinned
authorization context and its publisher signature is verified before any clause
here runs; the resource coordinates come from the pinned predicate schema and
from the officer-signed construction record; the instant is the revision's
``as_of``.  ``source_class`` remains signer-supplied and is *worthless on its
own*: it selects which grant would have to exist, and creates none.

**The clauses run in a fixed order and the first failure is the reported one.**
Two conforming implementations therefore return the same rejection, not merely
*a* rejection.  Q-9 (schema pin) and Q-10 (tenant) run before this, in the
admissibility pass, because the predicate specification clause (a) reads is
meaningless until they hold.  Q-4 to Q-8 and Q-11 -- the content checks -- run
*after* this, because an unauthorized source's payload should never have its
content evaluated at all.

**Nothing here is a boolean.**  Each clause has its own typed failure, so a
rejection says which of seven distinct things was wrong -- and an operator
debugging a legitimate agent is not left guessing between "wrong site" and
"wrong class", which is the difference the whole registry exists to make.

**What a failure discloses.**  Details are built from what the claimant already
supplied -- its own key reference, class, predicate, tenant and the coordinates
its own proposition ranges over -- and never from the snapshot.  A rejection
that named the grants a key *does* hold would turn every refused attestation
into a query against the registry.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from muster.core.authority.grants import AuthorityGrant, AuthorityRegistrySnapshot
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.scope import ResourceScope
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant


class AuthorityFailure(Enum):
    """Why a signed, well-formed attestation is not admissible evidence.

    One member per way authority can be absent.  There is deliberately no
    generic ``AUTHORITY_FAILED``: a single opaque reason would make "wrong
    site" and "wrong class" the same event in every log and every test, and the
    ratified adversarial requirement is precisely that they are different.
    """

    #  (a) the pinned bundle does not permit this class for this predicate.
    SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE = "SourceClassNotPermittedForPredicate"
    #  (b) no grant binds this key to the class it declared.
    UNAUTHORIZED_SOURCE_CLASS_FOR_KEY = "UnauthorizedSourceClassForKey"
    #  (b) two grants bind it.  Not resolved by precedence -- see below.
    AMBIGUOUS_AUTHORITY_GRANT = "AmbiguousAuthorityGrant"
    #  (c) the tenant chain does not close.
    CROSS_TENANT_AUTHORITY = "CrossTenantAuthority"
    #  (d) the key is not the one this snapshot binds to that principal.
    PRINCIPAL_MISMATCH = "PrincipalMismatch"
    #  (d) the proposition ranges over no resource coordinate at all, so there
    #  is nothing for a grant to have covered.  Refused rather than treated as
    #  "covers everything", which is what an empty required set would mean to a
    #  subset test.
    RESOURCE_SCOPE_UNDETERMINED = "ResourceScopeUndetermined"
    #  (d) the grant does not enumerate a coordinate this proposition needs.
    RESOURCE_SCOPE_NOT_AUTHORIZED = "ResourceScopeNotAuthorized"
    #  (e) the predicate is not in the grant's enumerated set.
    PREDICATE_NOT_AUTHORIZED_FOR_KEY = "PredicateNotAuthorizedForKey"
    #  (f) validity, split into its two directions.  The ratified contract
    #  names one ``AuthorityExpired``; reporting which end of the interval was
    #  missed is strictly more precise and never less fail-closed.
    AUTHORITY_NOT_YET_VALID = "AuthorityNotYetValid"
    AUTHORITY_EXPIRED = "AuthorityExpired"
    #  (f) the key is in the pinned revocation snapshot.
    KEY_REVOKED = "KeyRevoked"
    #  (f) grant, context and payload do not agree on the policy version.
    AUTHORIZATION_POLICY_VERSION_MISMATCH = "AuthorizationPolicyVersionMismatch"


@dataclass(frozen=True, slots=True)
class AuthorityError:
    """Which clause refused, and a detail derived only from the claim."""

    failure: AuthorityFailure
    detail: str


@dataclass(frozen=True, slots=True)
class SourceClaim:
    """What a receipt asserts about its own authority, before anything checks it.

    Every field here is signer-supplied.  That is the point: these are the
    *claims*, and Q-12 is what turns a claim into an entitlement or refuses to.
    """

    tenant_id: str
    signer_key_ref: str
    source_class: str
    proposition: SymbolRef
    authorization_policy_version: int


@dataclass(frozen=True, slots=True)
class AuthorityView:
    """The pinned authority state one rebuild judges every receipt against.

    Assembled once per rebuild from artifacts the revision named by digest --
    never from a receipt, never from a catalog, never from "whatever the
    registry says today".  Two cases pinning two snapshots get two views and
    two answers, and a historical case replays against the view its own pins
    describe.

    ``as_of`` is the revision's, so validity is judged against the instant the
    case is being decided as of and against nothing else.  There is no clock
    here; a rebuild replayed a year later admits exactly the receipts it
    admitted the first time.
    """

    snapshot: AuthorityRegistrySnapshot
    revocation: RevocationSnapshot
    tenant_id: str
    authorization_policy_version: int
    case_scope_coordinates: tuple[ResourceScope, ...]
    as_of: Instant


@dataclass(frozen=True, slots=True)
class RequiredScope:
    """The coordinates a grant must cover, and the kinds nothing could supply.

    Two fields rather than one, because "the grant does not cover this site"
    and "nobody said which site" are different findings with different fixes,
    and collapsing them would report a publisher problem as an operator one.
    ``undeterminable`` being non-empty is always a refusal.
    """

    coordinates: frozenset[ResourceScope]
    undeterminable: frozenset[str]


def required_coordinates(
    proposition: SymbolRef,
    arg_kinds: Sequence[str],
    resource_scope_kinds: Sequence[str],
    case_scope_coordinates: Iterable[ResourceScope],
) -> RequiredScope:
    """Resolve the resource coordinates Q-12(d) tests, for one proposition.

    For each scope kind the pinned schema declares for this predicate:

    * if the predicate's own argument list carries that kind, the value is the
      argument.  ``accepted_quantity(PO-4471)`` with argument kind
      ``PURCHASE_ORDER`` yields ``(PURCHASE_ORDER, PO-4471)``, so a grant has
      to enumerate that purchase order and no other;
    * otherwise the value comes from the case's own coordinates, which the
      officer signed into the construction record.  ``present_on_site(RAVI,
      SAT)`` scoped by ``SITE`` yields the case's site, because the proposition
      does not name one and the source must not be the one who decides;
    * if neither supplies it, the kind is **undeterminable**.  That is a
      refusal, never a pass: an unresolvable coordinate is exactly the state in
      which a subset test would succeed vacuously.

    A kind appearing more than once yields **every** one of its values, and all
    of them must be covered -- whether the repetition is in the argument list or
    in the case's coordinates.  A case spanning two sites needs a grant over
    both: keeping one and dropping the other would drop a *requirement*, and
    dropping a requirement widens authority.

    **Total, by construction.**  A proposition's arguments are signer-supplied,
    and ``ResourceScope`` refuses an empty or wildcard-shaped value by raising
    -- so building one from an argument without catching that would let any key
    whose signature verifies crash this function, before ``check_authority``
    has even looked at whether it holds a grant.  A coordinate that cannot be
    built is *undeterminable*, which is a refusal.  Q-12(d) must return a typed
    rejection for every input, or two conforming implementations do not return
    the same rejection -- one of them raises.

    The two sources this reads are the pinned schema and the officer-signed
    construction record.  The payload contributes argument *values* and nothing
    else, and no value it can carry produces anything but a coordinate or a
    refusal.
    """
    #  Grouped rather than keyed: a dict from kind to coordinate would keep one
    #  of a case's two sites and drop the other, and the dropped one is a
    #  requirement -- so the mistake would widen authority, which is the only
    #  direction that matters here.
    from_case: dict[str, set[ResourceScope]] = {}
    for scope in case_scope_coordinates:
        from_case.setdefault(scope.scope_kind, set()).add(scope)

    coordinates: set[ResourceScope] = set()
    undeterminable: set[str] = set()
    for kind in resource_scope_kinds:
        positions = [index for index, arg_kind in enumerate(arg_kinds) if arg_kind == kind]
        if positions:
            for index in positions:
                if index >= len(proposition.args):
                    #  The schema declares more argument kinds than the
                    #  reference carries.  ``spec_for`` refuses that mismatch
                    #  before this is reached, so arriving here means something
                    #  bypassed it -- and the safe reading of a missing
                    #  argument is not "any argument".
                    undeterminable.add(kind)
                    continue
                built = _coordinate(kind, proposition.args[index])
                if built is None:
                    undeterminable.add(kind)
                else:
                    coordinates.add(built)
            continue
        supplied = from_case.get(kind)
        if not supplied:
            undeterminable.add(kind)
        else:
            coordinates.update(supplied)
    return RequiredScope(frozenset(coordinates), frozenset(undeterminable))


def _coordinate(kind: str, value: str) -> ResourceScope | None:
    """A coordinate, or ``None`` where the value cannot be one.

    ``ResourceScope`` refuses an empty value and every wildcard spelling by
    raising, which is right for a publisher assembling a grant and wrong here:
    this value came off a signed payload an attacker wrote, so it is input and
    a refusal has to be a value.  ``None`` becomes ``undeterminable``, which
    ``check_authority`` treats as an unconditional rejection -- so a
    proposition over ``"*"`` is refused with a typed reason rather than
    crashing the admission path.
    """
    try:
        return ResourceScope(kind, value)
    except InvariantViolation:
        return None


def check_authority(
    claim: SourceClaim,
    permitted_source_classes: frozenset[str],
    required: RequiredScope,
    authority: AuthorityView,
) -> Result[AuthorityGrant, AuthorityError]:
    """Q-12(a) to (f), in the ratified order. Accepted iff every clause holds.

    Returns the grant that carried the decision, so a caller can record *which*
    authorization admitted a receipt rather than only that one did.
    """
    #  ---- (a) the bundle permits this class for this predicate ------------
    #
    #  Read from the pinned predicate schema, which is inside the signed bundle
    #  the revision names.  This is the clause a declared-but-unread field left
    #  open for two milestones: a permission list nothing compares against is
    #  not a control.
    if claim.source_class not in permitted_source_classes:
        return Err(
            AuthorityError(
                AuthorityFailure.SOURCE_CLASS_NOT_PERMITTED_FOR_PREDICATE,
                f"{claim.source_class} may not attest {claim.proposition.predicate_id}",
            )
        )

    #  ---- (b) this key holds that class -----------------------------------
    #
    #  Exactly one grant.  Zero is the ordinary rejection -- a worker key
    #  declaring a goods-receipt class resolves nothing.  More than one is a
    #  malformed snapshot, and it fails closed rather than being resolved by
    #  precedence: choosing the more permissive grant is how authority systems
    #  are defeated, and choosing the narrower one hides a publisher defect.
    matches = authority.snapshot.resolve(claim.signer_key_ref, claim.source_class)
    if not matches:
        return Err(
            AuthorityError(
                AuthorityFailure.UNAUTHORIZED_SOURCE_CLASS_FOR_KEY,
                f"{claim.signer_key_ref} holds no {claim.source_class} grant",
            )
        )
    if len(matches) > 1:
        return Err(
            AuthorityError(
                AuthorityFailure.AMBIGUOUS_AUTHORITY_GRANT,
                f"{len(matches)} grants bind {claim.signer_key_ref} to {claim.source_class}",
            )
        )
    grant = matches[0]

    #  ---- (c) tenant -------------------------------------------------------
    #
    #  A four-way equality, not a comparison against one authority.  The grant,
    #  the snapshot it came from, the revision being rebuilt and the payload
    #  must all name one tenant; any pair disagreeing means an artifact from
    #  one tenant is being read under another, whatever the store's keying says.
    if not (
        grant.tenant_scope == authority.snapshot.tenant_id == authority.tenant_id == claim.tenant_id
    ):
        return Err(
            AuthorityError(
                AuthorityFailure.CROSS_TENANT_AUTHORITY,
                f"{claim.tenant_id} does not hold this authority",
            )
        )
    #  The revocation snapshot is authority state too, and an untenanted one
    #  would be borrowable: a list published for one tenant must not decide
    #  another's revocations.
    if authority.revocation.tenant_id != authority.tenant_id:
        return Err(
            AuthorityError(
                AuthorityFailure.CROSS_TENANT_AUTHORITY,
                f"{claim.tenant_id} does not hold this revocation state",
            )
        )

    #  ---- (d) principal and resource scope ---------------------------------
    #
    #  The snapshot is the source directory: a key belongs to one institutional
    #  principal, and every grant it holds must agree about which.  A snapshot
    #  in which one key answers to two principals is refused on construction --
    #  this repeats the check because octets read back from a store went
    #  through no constructor an adversary could not also have gone around.
    expected = authority.snapshot.principal_for(claim.signer_key_ref)
    if expected is None or expected != grant.principal_id:
        return Err(
            AuthorityError(
                AuthorityFailure.PRINCIPAL_MISMATCH,
                f"{claim.signer_key_ref} is not bound to one principal",
            )
        )
    if required.undeterminable or not required.coordinates:
        #  Nothing to check is not the same as everything checked out.  An
        #  empty required set makes the subset test below vacuously true, so it
        #  is refused here instead: a predicate scoped by a kind neither its
        #  arguments nor the case supplies has no resource for a grant to have
        #  been written about, and a schema declaring no scope kind at all was
        #  already refused when the bundle loaded.
        return Err(
            AuthorityError(
                AuthorityFailure.RESOURCE_SCOPE_UNDETERMINED,
                f"{claim.proposition} has no determinable coordinate for "
                f"{', '.join(sorted(required.undeterminable)) or 'any declared kind'}",
            )
        )
    if not grant.covers(required.coordinates):
        #  Set inclusion over whole ``(kind, value)`` pairs.  No prefix rule
        #  exists anywhere on this path, which is what stops a grant over
        #  ``site-1`` from reaching ``site-10``.
        return Err(
            AuthorityError(
                AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED,
                f"{claim.signer_key_ref} is not authorized over "
                f"{', '.join(sorted(str(scope) for scope in required.coordinates))}",
            )
        )

    #  ---- (e) predicate ----------------------------------------------------
    if not grant.covers_predicate(claim.proposition.predicate_id):
        return Err(
            AuthorityError(
                AuthorityFailure.PREDICATE_NOT_AUTHORIZED_FOR_KEY,
                f"{claim.signer_key_ref} may not attest {claim.proposition.predicate_id}",
            )
        )

    #  ---- (f) validity, revocation and policy version ----------------------
    #
    #  ``[start, end)``.  Admitted at the microsecond before the end and
    #  refused at it, judged against the revision's ``as_of`` and never against
    #  a clock -- which is what makes the decision replay identically forever.
    if authority.as_of < grant.validity.start:
        return Err(
            AuthorityError(
                AuthorityFailure.AUTHORITY_NOT_YET_VALID,
                f"{claim.signer_key_ref} holds no authority at {authority.as_of}",
            )
        )
    if not grant.validity.contains(authority.as_of):
        return Err(
            AuthorityError(
                AuthorityFailure.AUTHORITY_EXPIRED,
                f"{claim.signer_key_ref} holds no authority at {authority.as_of}",
            )
        )
    if authority.revocation.revokes(claim.signer_key_ref):
        #  A revoked key's signature still verifies -- revocation withdraws
        #  authority, not mathematics -- which is exactly why this clause is
        #  here and not in the verifier.
        return Err(
            AuthorityError(AuthorityFailure.KEY_REVOKED, f"{claim.signer_key_ref} is revoked")
        )
    if not (
        grant.authorization_policy_version
        == authority.snapshot.authorization_policy_version
        == authority.authorization_policy_version
        == claim.authorization_policy_version
    ):
        #  No silent mapping between versions.  A grant issued under one
        #  authorization policy does not acquire the meaning a later, broader
        #  policy would have given it, and a receipt claiming a version its
        #  case did not pin is answering a question nobody asked.
        return Err(
            AuthorityError(
                AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH,
                f"the receipt claims authorization policy version "
                f"{claim.authorization_policy_version}",
            )
        )

    return Ok(grant)
