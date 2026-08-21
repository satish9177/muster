"""Assignments built by hand, for the tests that are about one agent.

The acceptance suite gets its assignments the way production does -- from the
planner, through the catalog, out of ``assign_request``.  The adversarial suite
needs something else: an assignment that is *deliberately wrong* in one named
way, which a correct dispatcher would never produce.

So these are built directly, and every helper varies exactly one thing from the
worked case: the site it names, the predicate it asks for, the class it
addresses, the instant it is decided at.  A helper that varied two would test
neither.
"""

from __future__ import annotations

from agent_tests.support.fleet import SATURDAY, SITE, WORKER
from muster.core.authority.scope import ResourceScope
from muster.core.evidence.acquisition import AcquisitionAssignment, AcquisitionTargetSpec
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest, DigestKind, digest_octets
from muster.domains.workforce.bundle import workforce_bundle

#  The instant the worked case is decided at.  Matches the kernel fixture, so a
#  receipt built against these assignments is admissible in that case.
AS_OF: Instant = 1_786_000_000_000_000
DEADLINE: Instant = AS_OF + 3_600_000_000

PRESENT = SymbolRef("present_on_site", (WORKER, SATURDAY))
DURATION = SymbolRef("on_site_duration", (WORKER, SATURDAY))
SCHEDULED = SymbolRef("scheduled", (WORKER, SATURDAY))
PAYABLE = SymbolRef("shift_payable_under_policy", (WORKER, SATURDAY))

SITE_ACCESS_CONTROL = "SITE_ACCESS_CONTROL"
HR_PAYROLL_SYSTEM = "HR_PAYROLL_SYSTEM"


def request_id(label: str = "worked-request") -> Digest:
    """A stable request identifier for a test that does not resolve one.

    Digested under the evidence-request domain so it is the *shape* of a real
    citation.  It resolves to nothing, which at admission means volunteered
    evidence -- a legitimate state, and the one these unit-level tests are in.
    """
    return digest_octets(DigestKind.EVIDENCE_REQUEST, label.encode("utf-8"))


def target(
    proposition: SymbolRef,
    *,
    subject: str = WORKER,
    source_class: str = SITE_ACCESS_CONTROL,
    scope: tuple[ResourceScope, ...] = (ResourceScope("SITE", SITE),),
) -> AcquisitionTargetSpec:
    """One target, resolved from the pinned bundle exactly as a dispatcher does.

    The sort, domain, layer, acquisition class and measurement class are read
    from the bundle rather than restated here, so a target built by a test is
    the same shape as one built by ``assign_request``.  What a caller varies is
    what an *attack* varies: the class addressed, the resource named, the
    subject asked about.
    """
    spec = workforce_bundle().predicate_schema.spec_for(proposition)
    assert spec is not None, f"the workforce bundle declares no {proposition}"
    return AcquisitionTargetSpec(
        proposition=proposition,
        subject=subject,
        value_sort=spec.value_sort,
        domain=spec.domain,
        layer=spec.layer,
        acquisition=spec.acquisition,
        permitted_source_classes=(source_class,),
        resource_scope=scope,
        measurement_class=spec.measurement_class,
    )


def assignment(
    *targets: AcquisitionTargetSpec,
    tenant_id: str,
    case_id: str,
    agent_id: str,
    as_of: Instant = AS_OF,
    cited: Digest | None = None,
) -> AcquisitionAssignment:
    """An assignment naming the given targets, bound to the worked case."""
    return AcquisitionAssignment(
        tenant_id=tenant_id,
        case_id=case_id,
        request_id=cited if cited is not None else request_id(),
        revision_semantic_digest=request_id("worked-revision"),
        predicate_schema_digest=workforce_bundle().predicate_schema.digest(),
        authorization_policy_version=1,
        as_of=as_of,
        deadline=DEADLINE,
        agent_id=agent_id,
        targets=tuple(targets),
    )


def site_assignment(
    *, tenant_id: str, case_id: str, agent_id: str, as_of: Instant = AS_OF
) -> AcquisitionAssignment:
    """The two observations the worked case actually asks the site for."""
    return assignment(
        target(PRESENT),
        target(DURATION),
        tenant_id=tenant_id,
        case_id=case_id,
        agent_id=agent_id,
        as_of=as_of,
    )
