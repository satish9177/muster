"""Resolving one durable request into one assignment per cataloged agent.

Everything an assignment carries is read from an artifact the source could not
choose:

* the **value sort, domain, layer and measurement class** come from the pinned
  bundle's predicate schema;
* the **permitted source class** is the bundle's set for the predicate
  intersected with the request target's -- both halves of Q-12(a), resolved
  once, here -- and then narrowed to the single class the route actually
  reached;
* the **resource coordinates** come from the same function check Q-12(d) calls,
  over the pinned schema's declared scope kinds and the *officer-signed*
  construction record.  A source that could name its own site would authorize
  itself, so the site is read from the record the officer signed and from
  nothing the source supplied;
* the **subject** comes from the construction record's declared subjects;
* the **schema pin and policy version** come from the bundle and from the
  authorization context the case pinned, so a reply that cites anything else
  is refused at admission rather than quietly reinterpreted;
* the **instant** is the revision's ``as_of``, because a receipt is admissible
  only inside a validity window containing it.

**Routing is by source class, and an ambiguous route is refused.**  A target
may permit more than one class; each is offered to discovery in canonical
order, and the request is deliverable only if exactly one class resolves to an
agent.  Two classes resolving to two different agents means the case could be
answered by either, and choosing the one that sorted first would make the
choice invisible -- so it is reported rather than arbitrated, exactly as
discovery reports two matching profiles rather than picking one.

**A target that cannot be routed does not sink the request.**  Acquiring one of
two observations still narrows a case, so unroutable targets are reported
alongside the deliverable assignments rather than replacing them.  A caller
that wants all-or-nothing can read the report and decline; a caller that would
rather have half the evidence does not have to argue with this function for it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.check import required_coordinates
from muster.core.authority.scope import ResourceScope
from muster.core.authority.signing import PublisherVerifier
from muster.core.case.revision import AuthorizationContext
from muster.core.catalog.discovery import DiscoveryQuery
from muster.core.catalog.profiles import AgentProfile
from muster.core.evidence.acquisition import AcquisitionAssignment, AcquisitionTargetSpec
from muster.core.evidence.requests import EvidenceRequest, EvidenceTarget
from muster.core.evidence.transcript import CaseConstructionRecord
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.times import Instant
from muster.core.wire.digests import Digest
from muster.platform.casework.ports import TenantScope
from muster.platform.catalog.route import CatalogResolutionError, route
from muster.policy.manifest import LoadedBundle


class AssignmentFailure(Enum):
    """Why a target could not be turned into something a source could answer."""

    #: The pinned bundle declares no such predicate at this arity.  The planner
    #: built the target from the same bundle, so this is corruption rather than
    #: an ordinary miss -- and it is still a value, not a raise.
    PREDICATE_NOT_DECLARED = "PREDICATE_NOT_DECLARED"
    #: The bundle's permitted classes and the request target's do not overlap.
    #: Nothing could answer it, and asking anyway would spend a signature on a
    #: receipt Q-12(a) refuses.
    NO_PERMITTED_SOURCE_CLASS = "NO_PERMITTED_SOURCE_CLASS"
    #: A scope kind the schema declares is supplied by neither the proposition
    #: nor the case.  Q-12(d) refuses an unresolvable coordinate rather than
    #: reading it as unrestricted, so the request is refused here too.
    RESOURCE_SCOPE_UNDETERMINABLE = "RESOURCE_SCOPE_UNDETERMINABLE"
    #: No proposition argument is a declared subject of this case and the case
    #: declares more than one, so provenance cannot be attributed.
    SUBJECT_UNDETERMINABLE = "SUBJECT_UNDETERMINABLE"
    #: No cataloged agent is a candidate.  The detail carries discovery's own
    #: typed reason -- unknown class, undeclared capability, uncovered
    #: resource, retired profile -- because those need different fixes.
    NO_AGENT_AVAILABLE = "NO_AGENT_AVAILABLE"
    #: Two permitted classes resolve to two different agents.  Refused, never
    #: arbitrated: routing evidence acquisition to whichever class sorted first
    #: would make the choice unrepeatable and invisible.
    AMBIGUOUS_ROUTE = "AMBIGUOUS_ROUTE"
    #: The catalog itself could not be resolved: absent, unreadable, signed by
    #: an untrusted publisher, or published for another tenant.
    CATALOG_UNAVAILABLE = "CATALOG_UNAVAILABLE"
    #: The target is well-formed and the assignment types refuse it -- a
    #: derived predicate, a normative layer, an empty scope.  Reported rather
    #: than raised, because a request is input to this function.
    TARGET_REFUSED = "TARGET_REFUSED"


@dataclass(frozen=True, slots=True)
class AssignmentError:
    failure: AssignmentFailure
    detail: str


@dataclass(frozen=True, slots=True)
class UnroutableTarget:
    """One proposition nobody can be asked for, and why."""

    target: EvidenceTarget
    error: AssignmentError


@dataclass(frozen=True, slots=True)
class AddressedAssignment:
    """One assignment together with the profile it is addressed to.

    The profile travels beside the assignment rather than inside it: an
    ``endpoint_ref`` is an operational address that changes when a deployment
    moves, and putting it in the artifact a source reads would invite a reader
    to treat "it came from this address" as a fact about authority.
    """

    profile: AgentProfile
    assignment: AcquisitionAssignment


@dataclass(frozen=True, slots=True)
class Assignments:
    """What one request resolved to: what can be asked, and what cannot."""

    deliverable: tuple[AddressedAssignment, ...]
    unroutable: tuple[UnroutableTarget, ...]


@dataclass(frozen=True, slots=True)
class _Resolved:
    """One target, resolved and routed."""

    profile: AgentProfile
    spec: AcquisitionTargetSpec


def assign_request(
    scope: TenantScope,
    verifier: PublisherVerifier,
    *,
    request: EvidenceRequest,
    construction: CaseConstructionRecord,
    authorization_context: AuthorizationContext,
    bundle: LoadedBundle,
    as_of: Instant,
    deadline: Instant,
) -> Assignments:
    """Resolve every target of one request, grouped by the agent that can answer.

    Total: every target ends up in exactly one of the two lists, and a target
    that cannot be resolved for any reason -- including one the value types
    refuse at construction -- becomes an ``UnroutableTarget`` rather than an
    exception.  A request is input, and input is refused with a value.
    """
    resolved: list[_Resolved] = []
    unroutable: list[UnroutableTarget] = []
    for target in request.targets:
        outcome = _resolve(scope, verifier, target=target, construction=construction, bundle=bundle)
        if isinstance(outcome, Err):
            unroutable.append(UnroutableTarget(target, outcome.error))
        else:
            resolved.append(outcome.value)

    return Assignments(
        deliverable=_group(
            resolved,
            request=request,
            predicate_schema_digest=bundle.predicate_schema.digest(),
            authorization_policy_version=authorization_context.authorization_policy_version,
            as_of=as_of,
            deadline=deadline,
        ),
        unroutable=tuple(unroutable),
    )


def _resolve(
    scope: TenantScope,
    verifier: PublisherVerifier,
    *,
    target: EvidenceTarget,
    construction: CaseConstructionRecord,
    bundle: LoadedBundle,
) -> Result[_Resolved, AssignmentError]:
    proposition = target.proposition
    spec = bundle.predicate_schema.spec_for(proposition)
    if spec is None:
        return Err(
            AssignmentError(
                AssignmentFailure.PREDICATE_NOT_DECLARED,
                f"the pinned bundle declares no {proposition.predicate_id} of this arity",
            )
        )

    #  Both halves of Q-12(a), intersected once.  A caller comparing against
    #  either half alone would apply one and forget the other, which is the
    #  shape the clause exists to prevent.
    permitted = frozenset(spec.permitted_source_classes) & frozenset(
        target.permitted_source_classes
    )
    if not permitted:
        return Err(
            AssignmentError(
                AssignmentFailure.NO_PERMITTED_SOURCE_CLASS,
                f"the bundle and the request agree on no source class for {proposition}",
            )
        )

    required = required_coordinates(
        proposition, spec.arg_kinds, spec.resource_scope_kinds, construction.case_scope_coordinates
    )
    if required.undeterminable:
        return Err(
            AssignmentError(
                AssignmentFailure.RESOURCE_SCOPE_UNDETERMINABLE,
                f"{proposition} declares scope kinds nothing supplies: "
                f"{', '.join(sorted(required.undeterminable))}",
            )
        )

    subject = _subject_of(proposition.args, construction.subject_refs)
    if subject is None:
        return Err(
            AssignmentError(
                AssignmentFailure.SUBJECT_UNDETERMINABLE,
                f"{proposition} names no declared subject of this case",
            )
        )

    coordinates = _ordered(required.coordinates)
    routed = _route_one(
        scope,
        verifier,
        predicate_id=proposition.predicate_id,
        permitted=permitted,
        coordinates=coordinates,
    )
    if isinstance(routed, Err):
        return Err(routed.error)
    profile = routed.value

    try:
        built = AcquisitionTargetSpec(
            proposition=proposition,
            subject=subject,
            value_sort=spec.value_sort,
            domain=spec.domain,
            layer=spec.layer,
            acquisition=spec.acquisition,
            #  The *routed* class alone, not every class the intersection
            #  allowed.  An assignment addressed to the badge reader that also
            #  listed the payroll system would be telling one source that
            #  another was acceptable -- information it has no use for, and one
            #  field closer to a source choosing its own class.
            permitted_source_classes=(profile.source_class,),
            resource_scope=coordinates,
            measurement_class=spec.measurement_class,
        )
    except InvariantViolation as violation:
        return Err(AssignmentError(AssignmentFailure.TARGET_REFUSED, str(violation)))
    return Ok(_Resolved(profile, built))


def _route_one(
    scope: TenantScope,
    verifier: PublisherVerifier,
    *,
    predicate_id: str,
    permitted: frozenset[str],
    coordinates: tuple[ResourceScope, ...],
) -> Result[AgentProfile, AssignmentError]:
    """The one cataloged agent that could answer, across every permitted class.

    Each class is asked separately because discovery matches one class exactly
    -- there is no prefix rule, no scoring and no best match anywhere in it --
    and the classes are asked in sorted order so that the *reported* failure of
    a request nobody can answer does not depend on set iteration order.
    """
    candidates: list[AgentProfile] = []
    failures: list[str] = []
    catalog_failures: list[str] = []
    for source_class in sorted(permitted):
        found = route(
            scope,
            verifier,
            DiscoveryQuery(
                tenant_id=scope.tenant_id,
                source_class=source_class,
                predicate_id=predicate_id,
                resource_scope=coordinates,
            ),
        )
        if isinstance(found, Ok):
            candidates.append(found.value)
            continue
        detail = f"{source_class}: {found.error.failure.value}: {found.error.detail}"
        failures.append(detail)
        if isinstance(found.error, CatalogResolutionError):
            catalog_failures.append(detail)

    if len(candidates) > 1:
        return Err(
            AssignmentError(
                AssignmentFailure.AMBIGUOUS_ROUTE,
                f"{len(candidates)} agents can answer {predicate_id}; "
                "a route is refused, not arbitrated",
            )
        )
    if candidates:
        return Ok(candidates[0])
    if catalog_failures:
        #  Reported apart from "no agent", because they need different fixes:
        #  an unresolvable catalog is a publication problem and an uncovered
        #  resource is a fleet-coverage one, and telling an operator to publish
        #  an agent when the catalog will not verify sends them to the wrong
        #  problem entirely.
        return Err(
            AssignmentError(AssignmentFailure.CATALOG_UNAVAILABLE, "; ".join(catalog_failures))
        )
    return Err(AssignmentError(AssignmentFailure.NO_AGENT_AVAILABLE, "; ".join(failures)))


def _ordered(coordinates: frozenset[ResourceScope]) -> tuple[ResourceScope, ...]:
    """A stable coordinate order, so two runs produce identical octets."""
    return tuple(sorted(coordinates, key=lambda scope: (scope.scope_kind, scope.scope_value)))


def _subject_of(args: tuple[str, ...], subject_refs: tuple[str, ...]) -> str | None:
    """Which declared subject an observation is about.

    The first proposition argument the construction record declares as a
    subject.  If none is, and the case declares exactly one subject, that one --
    which is how a proposition whose arguments are all resources, such as a
    quantity over a purchase order, still attributes provenance.  Otherwise
    ``None``: a receipt naming a subject the case never declared is provenance
    nobody can check, and guessing which of several it meant would be worse.
    """
    declared = set(subject_refs)
    for arg in args:
        if arg in declared:
            return arg
    if len(subject_refs) == 1:
        return subject_refs[0]
    return None


def _group(
    resolved: list[_Resolved],
    *,
    request: EvidenceRequest,
    predicate_schema_digest: Digest,
    authorization_policy_version: int,
    as_of: Instant,
    deadline: Instant,
) -> tuple[AddressedAssignment, ...]:
    """One assignment per agent, in a deterministic order.

    Grouped by ``(agent_id, version)`` because that is what a catalog snapshot
    makes unique, and ordered by it because two runs of the same request must
    produce the same sequence of calls -- an operator comparing two runs should
    be reading a difference in the case, not in a dictionary's iteration order.

    Target order inside an assignment is the *request's* order, which is the
    order the planner authored.  Re-sorting it here would be a second opinion
    about a sequence somebody already fixed.
    """
    by_agent: dict[tuple[str, int], tuple[AgentProfile, list[AcquisitionTargetSpec]]] = {}
    for entry in resolved:
        key = entry.profile.identity()
        if key not in by_agent:
            by_agent[key] = (entry.profile, [])
        by_agent[key][1].append(entry.spec)

    assignments: list[AddressedAssignment] = []
    for key in sorted(by_agent):
        profile, targets = by_agent[key]
        assignments.append(
            AddressedAssignment(
                profile,
                AcquisitionAssignment(
                    tenant_id=request.tenant_id,
                    case_id=request.case_id,
                    request_id=request.digest(),
                    revision_semantic_digest=request.revision_semantic_digest,
                    predicate_schema_digest=predicate_schema_digest,
                    authorization_policy_version=authorization_policy_version,
                    as_of=as_of,
                    deadline=deadline,
                    agent_id=profile.agent_id,
                    targets=tuple(targets),
                ),
            )
        )
    return tuple(assignments)
