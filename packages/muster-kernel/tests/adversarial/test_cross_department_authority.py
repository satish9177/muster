"""The authority and catalog layers are not workforce-specific.

A structural proof, not a procurement demo.  What is claimed and shown is
exactly this: **a second institutional domain runs through the generic layer
without a line of authority or catalog production code changing.**

The way to show it is to build one.  Everything below is procurement -- a
goods-receipt system, purchase orders, a receiving warehouse, an
``accepted_quantity`` predicate -- and none of it exists anywhere in the
production tree.  It is declared here, as data, and Q-12 and discovery work
over it because they were written against coordinates and enumerations rather
than against sites and workers.

The negative half matters as much: a test that the generic layer *mentions* no
workforce vocabulary.  A layer that happened to work for procurement while
carrying an ``employee_id`` field would be one refactor from being workforce
again.
"""

from __future__ import annotations

import pathlib

from muster.core.authority.check import (
    AuthorityFailure,
    AuthorityView,
    SourceClaim,
    check_authority,
    required_coordinates,
)
from muster.core.authority.grants import AuthorityGrant, AuthorityRegistrySnapshot
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.authority.scope import ResourceScope
from muster.core.catalog.discovery import DiscoveryFailure, DiscoveryQuery, discover
from muster.core.catalog.profiles import (
    AgentCatalogSnapshot,
    AgentLifecycle,
    AgentProfile,
    canonical_profiles,
)
from muster.core.results import Err, Ok
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import HalfOpenInterval
from muster.core.wire.digests import Digest

#  ---- a second institutional domain, declared here and nowhere else --------

TENANT = "GAMMA"
WAREHOUSE = "WH-1"
GOODS_RECEIPT_KEY = "key-goods-receipt-1"
SOURCE_GOODS_RECEIPT = "GOODS_RECEIPT_SYSTEM"

PURCHASE_ORDER = "PO-4471"
OTHER_ORDER = "PO-9999"

ACCEPTED_QUANTITY = SymbolRef("accepted_quantity", (PURCHASE_ORDER,))

#  The pinned schema's declarations for this predicate.  Authority over it is
#  scoped by purchase order, and the predicate's own argument supplies the
#  value -- so a grant enumerates an order and reaches no other.
ARG_KINDS = ("PURCHASE_ORDER",)
SCOPE_KINDS = ("PURCHASE_ORDER",)
PERMITTED = frozenset({SOURCE_GOODS_RECEIPT})

POLICY_VERSION = 7
WINDOW = HalfOpenInterval(1_700_000_000_000_000, 1_800_000_000_000_000)
NOW = 1_750_000_000_000_000


def _grant(order: str = PURCHASE_ORDER) -> AuthorityGrant:
    return AuthorityGrant(
        key_ref=GOODS_RECEIPT_KEY,
        principal_id=WAREHOUSE,
        tenant_scope=TENANT,
        source_class=SOURCE_GOODS_RECEIPT,
        permitted_predicates=("accepted_quantity",),
        resource_scope=(ResourceScope("PURCHASE_ORDER", order),),
        validity=WINDOW,
        authorization_policy_version=POLICY_VERSION,
    )


def _snapshot(*grants: AuthorityGrant) -> AuthorityRegistrySnapshot:
    return AuthorityRegistrySnapshot(
        registry_id="procurement-registry-1",
        tenant_id=TENANT,
        authorization_policy_version=POLICY_VERSION,
        grants=grants,
        published_at=WINDOW.start,
    )


def _view(snapshot: AuthorityRegistrySnapshot) -> AuthorityView:
    return AuthorityView(
        snapshot=snapshot,
        revocation=RevocationSnapshot("procurement-revocation-1", TENANT, (), WINDOW.start),
        tenant_id=TENANT,
        authorization_policy_version=POLICY_VERSION,
        #  A procurement case declares a receiving location rather than a site.
        #  The predicate does not use it -- its order comes from its own
        #  argument -- and it is here to show that a case-level coordinate of a
        #  kind the layer has never heard of is carried without complaint.
        case_scope_coordinates=(ResourceScope("RECEIVING_LOCATION", "DOCK-3"),),
        as_of=NOW,
    )


def _claim(proposition: SymbolRef = ACCEPTED_QUANTITY, **changes: object) -> SourceClaim:
    base: dict[str, object] = {
        "tenant_id": TENANT,
        "signer_key_ref": GOODS_RECEIPT_KEY,
        "source_class": SOURCE_GOODS_RECEIPT,
        "proposition": proposition,
        "authorization_policy_version": POLICY_VERSION,
    }
    base.update(changes)
    return SourceClaim(**base)  # type: ignore[arg-type]


def _check(claim: SourceClaim, snapshot: AuthorityRegistrySnapshot) -> object:
    return check_authority(
        claim,
        PERMITTED,
        required_coordinates(
            claim.proposition, ARG_KINDS, SCOPE_KINDS, _view(snapshot).case_scope_coordinates
        ),
        _view(snapshot),
    )


#  ---- authority, in a domain the layer was not designed around --------------


def test_a_procurement_grant_authorizes_a_procurement_attestation() -> None:
    """The whole point: this passes, and no production code changed to allow it."""
    outcome = _check(_claim(), _snapshot(_grant()))
    assert isinstance(outcome, Ok), outcome
    assert outcome.value.principal_id == WAREHOUSE


def test_a_grant_over_one_purchase_order_does_not_reach_another() -> None:
    """Q-12(d), with the coordinate coming from the proposition's own argument."""
    outcome = _check(_claim(SymbolRef("accepted_quantity", (OTHER_ORDER,))), _snapshot(_grant()))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.RESOURCE_SCOPE_NOT_AUTHORIZED


def test_a_procurement_key_cannot_attest_a_predicate_it_was_not_granted() -> None:
    """Q-12(e), with a procurement predicate."""
    outcome = _check(
        _claim(SymbolRef("delivery_temperature", (PURCHASE_ORDER,))), _snapshot(_grant())
    )
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.PREDICATE_NOT_AUTHORIZED_FOR_KEY


def test_the_policy_version_of_a_second_domain_is_its_own() -> None:
    """Nothing in the layer assumes a version number, a tenant name or an epoch."""
    outcome = _check(_claim(authorization_policy_version=1), _snapshot(_grant()))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is AuthorityFailure.AUTHORIZATION_POLICY_VERSION_MISMATCH


#  ---- the fleet, in the same domain -----------------------------------------


def test_a_procurement_agent_is_discovered_and_grants_nothing() -> None:
    """Routing works, and the separation holds in a second domain too."""
    profile = AgentProfile(
        agent_id="agent-goods-receipt",
        version=1,
        tenant_id=TENANT,
        principal_id=WAREHOUSE,
        source_class=SOURCE_GOODS_RECEIPT,
        acquirable_predicates=("accepted_quantity",),
        resource_scope=(ResourceScope("PURCHASE_ORDER", PURCHASE_ORDER),),
        endpoint_ref="local://agent-goods-receipt",
        lifecycle=AgentLifecycle.ACTIVE,
    )
    catalog = AgentCatalogSnapshot(
        catalog_id="procurement-catalog-1",
        tenant_id=TENANT,
        profiles=canonical_profiles((profile,)),
        published_at=WINDOW.start,
        authority_registry_snapshot_digest=Digest(bytes(32)),
    )
    found = discover(
        catalog,
        DiscoveryQuery(
            tenant_id=TENANT,
            source_class=SOURCE_GOODS_RECEIPT,
            predicate_id="accepted_quantity",
            resource_scope=(ResourceScope("PURCHASE_ORDER", PURCHASE_ORDER),),
        ),
    )
    assert isinstance(found, Ok), found
    assert found.value.endpoint_ref == "local://agent-goods-receipt"

    #  And with an empty registry, the same profile confers nothing.
    empty = _snapshot()
    assert isinstance(_check(_claim(), empty), Err)

    other_order = discover(
        catalog,
        DiscoveryQuery(
            tenant_id=TENANT,
            source_class=SOURCE_GOODS_RECEIPT,
            predicate_id="accepted_quantity",
            resource_scope=(ResourceScope("PURCHASE_ORDER", OTHER_ORDER),),
        ),
    )
    assert isinstance(other_order, Err)
    assert other_order.error.failure is DiscoveryFailure.RESOURCE_NOT_COVERED


#  ---- the negative half -----------------------------------------------------

#  Vocabulary that would mean the generic layer had learned one domain's
#  business.  A *field* named any of these would be the finding; the words
#  appearing in a comment would not, so the check is over source that has had
#  its comments and docstrings removed.
WORKFORCE_VOCABULARY = (
    "employee",
    "employee_id",
    "worker_id",
    "timesheet",
    "payroll",
    "roster",
    "shift",
    "badge",
    "attendance",
    "site_id",
    "department",
)

GENERIC_LAYER = (
    "packages/muster-kernel/src/muster/core/authority",
    "packages/muster-kernel/src/muster/core/catalog",
    "packages/muster-platform/src/muster/platform/authority",
    "packages/muster-platform/src/muster/platform/catalog",
)


def _code_of(path: pathlib.Path) -> str:
    """The module's source with comments and string literals removed.

    Tokenised rather than regexed: ``SITE`` appears in several docstrings here
    as an *example*, and a check that could not tell an example from a
    declaration would either fail on prose or be widened until it passed on
    anything.
    """
    import io
    import tokenize

    kept: list[str] = []
    with path.open("rb") as handle:
        for token in tokenize.tokenize(io.BufferedReader(handle).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            kept.append(token.string)
    return " ".join(kept).lower()


def test_the_generic_layer_names_no_workforce_concept() -> None:
    """No identifier in the authority or catalog layer belongs to one domain.

    The layer is generic because it was written over coordinates and
    enumerations, and this is the test that keeps it that way: a future
    milestone adding ``site_id`` to a grant for convenience fails here rather
    than being noticed when the second department arrives.
    """
    root = pathlib.Path(__file__).resolve().parents[4]
    inspected = 0
    for package in GENERIC_LAYER:
        directory = root / package
        assert directory.is_dir(), package
        for module in sorted(directory.rglob("*.py")):
            code = _code_of(module)
            inspected += 1
            for word in WORKFORCE_VOCABULARY:
                assert word not in code, f"{module.name} declares {word!r}"
    assert inspected >= 8, inspected


def test_the_generic_layer_names_no_domain_bundle() -> None:
    """And imports none, which is the stronger form of the same statement."""
    root = pathlib.Path(__file__).resolve().parents[4]
    for package in GENERIC_LAYER:
        for module in sorted((root / package).rglob("*.py")):
            source = module.read_text(encoding="utf-8")
            assert "muster.domains" not in source, module.name
