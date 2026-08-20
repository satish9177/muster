"""Deterministic discovery: which cataloged agent could be asked for this?

    "Which currently cataloged agent is a candidate to acquire predicate P
     for resource R in tenant T?"

That is the whole question, and the answer is a *candidate*, not a permission.
Two properties make the distinction mechanical rather than rhetorical:

* discovery reads a catalog snapshot and nothing else.  It takes no authority
  snapshot, no revocation snapshot and no grant, so there is no path by which
  it could consult -- or confer -- authority;
* Q-12 reads an authority snapshot and nothing else.  It takes no catalog and
  no profile, so a profile claiming a capability contributes nothing to an
  admission decision.  Route to the agent discovery names, and its attestation
  is still judged from the registry when it comes back.

**Matching is exact and total.**  Tenant, source class, predicate membership,
resource coverage and lifecycle are each an equality or a set membership; there
is no prefix rule, no scoring, no "best match" and no fallback.  A query that
matches nothing is answered with a typed absence naming which constraint
excluded every candidate, which is what an operator needs -- and a query that
matches more than one active agent is **refused**, because routing evidence
acquisition to whichever profile sorted first would make the choice invisible
and unrepeatable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.authority.scope import ResourceScope
from muster.core.catalog.profiles import AgentCatalogSnapshot, AgentProfile
from muster.core.results import Err, InvariantViolation, Ok, Result


class DiscoveryFailure(Enum):
    """Why no single candidate was returned.

    Distinct members rather than one "not found", because the operational
    responses differ completely: a wrong tenant is a caller defect, an
    unsupported capability is a fleet-coverage gap, a stale profile is a
    rollout that has not finished, and an ambiguous match is a catalog that
    needs correcting before anything is routed at all.
    """

    WRONG_TENANT = "WRONG_TENANT"
    #: No active profile presents the requested source class.
    NO_SUCH_SOURCE_CLASS = "NO_SUCH_SOURCE_CLASS"
    #: A profile of that class exists but declares no such acquisition.
    CAPABILITY_NOT_DECLARED = "CAPABILITY_NOT_DECLARED"
    #: A capable profile exists but does not cover the resource asked about.
    RESOURCE_NOT_COVERED = "RESOURCE_NOT_COVERED"
    #: Every otherwise-matching profile is retired.
    NO_ACTIVE_PROFILE = "NO_ACTIVE_PROFILE"
    #: Two or more active profiles match.  Refused, never arbitrated.
    AMBIGUOUS_CANDIDATE = "AMBIGUOUS_CANDIDATE"


@dataclass(frozen=True, slots=True)
class DiscoveryError:
    failure: DiscoveryFailure
    detail: str


@dataclass(frozen=True, slots=True)
class DiscoveryQuery:
    """What the control plane needs acquired, stated as coordinates.

    ``source_class`` is part of the query rather than inferred from the
    predicate: the pinned bundle already says which classes may attest a
    predicate, and discovery's job is to find the agent presenting one of them,
    not to decide which class a predicate deserves.
    """

    tenant_id: str
    source_class: str
    predicate_id: str
    resource_scope: tuple[ResourceScope, ...]

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.source_class or not self.predicate_id:
            raise InvariantViolation("a discovery query names a tenant, a class and a predicate")
        if not self.resource_scope:
            #  Discovery over "any resource" would return an agent that covers
            #  something, which is exactly the answer that later fails Q-12(d)
            #  and wastes a signature.  Refused at the query.
            raise InvariantViolation("a discovery query names at least one resource coordinate")


def discover(
    catalog: AgentCatalogSnapshot, query: DiscoveryQuery
) -> Result[AgentProfile, DiscoveryError]:
    """The single active profile that could be asked, or a typed refusal.

    The narrowing order is the reporting order: each stage is applied to what
    the previous one left, so the failure returned names the *first* constraint
    that emptied the candidate set.  Reporting "resource not covered" when no
    agent of that class exists at all would send an operator to the wrong
    problem.
    """
    if catalog.tenant_id != query.tenant_id:
        #  A catalog is published per tenant and read under one.  Reaching here
        #  means a caller resolved one tenant's catalog and asked it about
        #  another's work, and answering would be a cross-tenant disclosure --
        #  the *existence* of a matching agent is itself information.
        return Err(
            DiscoveryError(
                DiscoveryFailure.WRONG_TENANT,
                f"a catalog for {catalog.tenant_id!r} was asked about {query.tenant_id!r}",
            )
        )

    #  Narrowed twice: once over the agents that could actually be routed to,
    #  and once over every profile.  The second run is only ever used to tell
    #  two absences apart.
    #
    #  Filtering lifecycle *last* was wrong, and wrong in the way staged
    #  reporting exists to prevent: an active agent that lacks the resource,
    #  beside a retired one that has it, reported "every candidate is retired"
    #  -- which sends an operator to finish a rollout when the real problem is
    #  that no live agent covers the site.
    mine = tuple(profile for profile in catalog.profiles if profile.tenant_id == query.tenant_id)
    routable = _narrow(tuple(profile for profile in mine if profile in catalog.active()), query)
    if isinstance(routable, Ok):
        candidates = routable.value
        if len(candidates) > 1:
            return Err(
                DiscoveryError(
                    DiscoveryFailure.AMBIGUOUS_CANDIDATE,
                    f"{len(candidates)} active agents match; a route is refused, not arbitrated",
                )
            )
        return Ok(candidates[0])

    #  The active set emptied.  If the same narrowing succeeds over every
    #  profile, what emptied it was the lifecycle and nothing else -- which is
    #  the state a half-finished rollout leaves, and is worth its own name.
    if isinstance(_narrow(mine, query), Ok):
        return Err(
            DiscoveryError(
                DiscoveryFailure.NO_ACTIVE_PROFILE,
                f"every {query.source_class} candidate for {query.predicate_id} is retired",
            )
        )
    return routable


def _narrow(
    profiles: tuple[AgentProfile, ...], query: DiscoveryQuery
) -> Result[tuple[AgentProfile, ...], DiscoveryError]:
    """Class, then capability, then resource -- reporting the first to empty.

    Returns the survivors rather than one profile, because "how many survived"
    is the caller's question and answering it here would mean answering it
    twice, once per narrowing.
    """
    by_class = tuple(profile for profile in profiles if profile.source_class == query.source_class)
    if not by_class:
        return Err(
            DiscoveryError(
                DiscoveryFailure.NO_SUCH_SOURCE_CLASS,
                f"no {query.source_class} agent is cataloged",
            )
        )
    capable = tuple(
        profile for profile in by_class if query.predicate_id in profile.acquirable_predicates
    )
    if not capable:
        return Err(
            DiscoveryError(
                DiscoveryFailure.CAPABILITY_NOT_DECLARED,
                f"no {query.source_class} agent acquires {query.predicate_id}",
            )
        )
    required = set(query.resource_scope)
    covering = tuple(profile for profile in capable if required <= set(profile.resource_scope))
    if not covering:
        return Err(
            DiscoveryError(
                DiscoveryFailure.RESOURCE_NOT_COVERED,
                f"no {query.source_class} agent covers "
                f"{', '.join(sorted(str(scope) for scope in required))}",
            )
        )
    return Ok(covering)
