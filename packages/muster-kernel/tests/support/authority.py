"""Authority fixtures for the kernel suite.

Two jobs, and keeping them apart is what stops the suite quietly weakening.

*For tests that are **not** about authority* -- relation lowering, the normative
barrier, the codec -- :func:`granting` builds a view that authorizes exactly the
claim being made.  Those tests were written to ask one question and should go
on asking it, so the authority input is arranged to be satisfied rather than
removed.  There is no "skip Q-12" switch anywhere, in production or here: a
bypass that exists for tests is a bypass.

*For tests that **are** about authority*, the builders below are deliberately
low-level -- a grant is assembled field by field -- so an adversarial test
states the exact thing it is varying and inherits no defaults that might be
doing the work for it.
"""

from __future__ import annotations

from muster.core.authority.check import AuthorityView, SourceClaim, required_coordinates
from muster.core.authority.grants import AuthorityGrant, AuthorityRegistrySnapshot, canonical_grants
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.scope import ResourceScope
from muster.core.evidence.relations import PredicateInfo
from muster.core.values.classification import EvidenceLayer
from muster.core.values.sorts import Domain, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval, Instant

TENANT = "ALPHA"
REGISTRY_ID = "authority-registry-1"
REVOCATION_ID = "revocation-registry-1"

SITE_A = "SITE-A"
SITE_B = "SITE-B"
EMPLOYER = "EMPLOYER-1"

SITE_A_KEY = "key-site-a-1"
SITE_B_KEY = "key-site-b-1"
PAYROLL_KEY = "key-hr-payroll-1"
WORKER_KEY = "key-worker-ravi-1"

SOURCE_SITE_ACCESS = "SITE_ACCESS_CONTROL"
SOURCE_PAYROLL = "HR_PAYROLL_SYSTEM"
SOURCE_GOODS_RECEIPT = "GOODS_RECEIPT_SYSTEM"

POLICY_VERSION = 1
NOW: Instant = 1_786_000_000_000_000
FOREVER = HalfOpenInterval(1_785_000_000_000_000, 1_790_000_000_000_000)

SITE_SCOPE = (ResourceScope("SITE", SITE_A),)
EMPLOYER_SCOPE = (ResourceScope("EMPLOYER", EMPLOYER),)
CASE_COORDINATES = (ResourceScope("SITE", SITE_A), ResourceScope("EMPLOYER", EMPLOYER))


def grant(
    *,
    key_ref: str,
    principal_id: str,
    source_class: str,
    predicates: tuple[str, ...],
    scope: tuple[ResourceScope, ...],
    tenant_id: str = TENANT,
    validity: HalfOpenInterval = FOREVER,
    policy_version: int = POLICY_VERSION,
) -> AuthorityGrant:
    return AuthorityGrant(
        key_ref=key_ref,
        principal_id=principal_id,
        tenant_scope=tenant_id,
        source_class=source_class,
        permitted_predicates=predicates,
        resource_scope=scope,
        validity=validity,
        authorization_policy_version=policy_version,
    )


def snapshot(
    *grants: AuthorityGrant,
    tenant_id: str = TENANT,
    policy_version: int = POLICY_VERSION,
) -> AuthorityRegistrySnapshot:
    return AuthorityRegistrySnapshot(
        registry_id=REGISTRY_ID,
        tenant_id=tenant_id,
        authorization_policy_version=policy_version,
        grants=canonical_grants(grants),
        published_at=FOREVER.start,
    )


def revocation(*revoked: str, tenant_id: str = TENANT) -> RevocationSnapshot:
    return RevocationSnapshot(
        registry_id=REVOCATION_ID,
        tenant_id=tenant_id,
        revoked_key_refs=tuple(sorted(revoked)),
        published_at=FOREVER.start,
    )


def view(
    registry: AuthorityRegistrySnapshot,
    revoked: RevocationSnapshot | None = None,
    *,
    tenant_id: str = TENANT,
    coordinates: tuple[ResourceScope, ...] = CASE_COORDINATES,
    as_of: Instant = NOW,
    policy_version: int = POLICY_VERSION,
) -> AuthorityView:
    return AuthorityView(
        snapshot=registry,
        revocation=revoked if revoked is not None else revocation(tenant_id=tenant_id),
        tenant_id=tenant_id,
        authorization_policy_version=policy_version,
        case_scope_coordinates=coordinates,
        as_of=as_of,
    )


def claim(
    proposition: SymbolRef,
    *,
    key_ref: str = SITE_A_KEY,
    source_class: str = SOURCE_SITE_ACCESS,
    tenant_id: str = TENANT,
    policy_version: int = POLICY_VERSION,
) -> SourceClaim:
    return SourceClaim(
        tenant_id=tenant_id,
        signer_key_ref=key_ref,
        source_class=source_class,
        proposition=proposition,
        authorization_policy_version=policy_version,
    )


def info(
    value_sort: Sort,
    domain: Domain,
    layer: EvidenceLayer,
    *,
    permitted: frozenset[str] = frozenset({SOURCE_SITE_ACCESS}),
    arg_kinds: tuple[str, ...] = ("WORKER", "DAY"),
    scope_kinds: tuple[str, ...] = ("SITE",),
) -> PredicateInfo:
    return PredicateInfo(
        value_sort=value_sort,
        domain=domain,
        layer=layer,
        permitted_source_classes=permitted,
        arg_kinds=arg_kinds,
        resource_scope_kinds=scope_kinds,
    )


def granting(spec: PredicateInfo, statement: SourceClaim) -> AuthorityView:
    """A view under which exactly this claim is authorized, and nothing more.

    For tests whose subject is elsewhere.  The grant is minted to fit the claim
    -- its key, its class, its predicate, and the case's site -- so Q-12 passes
    and the test's own assertion is what fails when the code under test is
    wrong.  It is not a bypass: the check still runs, over a real snapshot, and
    a test that changed the claim without changing this view would find Q-12
    refusing it, which is the correct answer.
    """
    #  Resolved by the production function rather than by a second copy of its
    #  rules.  A fixture that computed coordinates its own way could drift from
    #  what Q-12(d) asks for, and the drift would show up as tests passing.
    required = required_coordinates(
        statement.proposition, spec.arg_kinds, spec.resource_scope_kinds, CASE_COORDINATES
    )
    assert not required.undeterminable, required.undeterminable
    scope = (
        tuple(sorted(required.coordinates, key=lambda item: (item.scope_kind, item.scope_value)))
        or SITE_SCOPE
    )
    return view(
        snapshot(
            grant(
                key_ref=statement.signer_key_ref,
                principal_id=SITE_A,
                source_class=statement.source_class,
                predicates=(statement.proposition.predicate_id,),
                scope=scope,
                tenant_id=statement.tenant_id,
                policy_version=statement.authorization_policy_version,
            ),
            tenant_id=statement.tenant_id,
            policy_version=statement.authorization_policy_version,
        ),
        tenant_id=statement.tenant_id,
        policy_version=statement.authorization_policy_version,
    )
