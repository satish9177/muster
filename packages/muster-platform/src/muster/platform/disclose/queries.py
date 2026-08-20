"""``get_my_view``: the imperative boundary, and the one that must not take an audience.

The signature is the control.  There is **no** ``audience_class`` parameter and
there must never be one -- not an optional one, not one that is validated, not
one that is "only used when the caller is an operator".  A view built for the
wrong audience is internally perfect, so a parameter that could name one is a
parameter that could hand a participant somebody else's disclosure with every
downstream check passing.

What the caller may supply is a *principal*, which an identity layer verified,
and optionally the role they are **acting as**, which can only narrow the set
they already hold.  Everything else is resolved here:

    the case's parties      from the signed construction record
    the auditor role        from the operator directory
    the outcome             from the replayed certificate
    the entry               from the bundle's pinned disclosure policy
    the leaves              from the entry's permitted paths

**And it does not take a clock either.**  A view is a function of the head, the
artifacts it pins and the pinned policy; there is no deadline to compare against
and no expiry to project.  A ``now`` here could only be recorded, and a recorded
instant nobody checks is a field that looks like a control and is not one.
Status is where the clock belongs, and status is a different query.

**Only the head's revision is disclosable.**  The commitment is looked up for
the revision the head currently names, so there is no way to ask for a view of
a superseded revision -- not because the request is rejected, but because
nothing in the query names a revision at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.results import Err, Ok, Result
from muster.platform.casework.snapshot import read_published
from muster.platform.commit.publish import Commitment, CommitmentRejection, read_commitment
from muster.platform.disclose.audience import (
    AudienceRejection,
    DisclosureContext,
    Principal,
    PrincipalDirectory,
    resolve_audience,
)
from muster.platform.disclose.policy import PolicyError, resolve_entry
from muster.platform.disclose.views import View, build_view


@dataclass(frozen=True, slots=True)
class DisclosureService:
    """Commitment access plus the directory that says who the auditors are."""

    commitment: Commitment
    directory: PrincipalDirectory


class DisclosureFailure(Enum):
    #: There is no case here for this caller.  One value and one detail string
    #: for four distinguishable internal states -- the case is absent, it is
    #: unreadable, the caller is party to no role in it, or the role they named
    #: is not theirs -- because **the existence of a case is itself a
    #: disclosure**, and a caller who can tell those apart can enumerate a
    #: tenant's case identifiers.  Which of the four it was belongs in an
    #: operator's audit trail, not in the caller's result.
    CASE_NOT_VISIBLE = "CASE_NOT_VISIBLE"
    #: The head's revision has no published commitment, or the one it has does
    #: not match the record.
    COMMITMENT_REFUSED = "COMMITMENT_REFUSED"
    #: The pinned policy has no entry for this outcome, audience and context.
    #: A refusal, and specifically not an empty view: an operator's omission
    #: must not be indistinguishable from a deliberate silence.
    NOT_DISCLOSABLE = "NOT_DISCLOSABLE"


#: The one thing a refused caller is told.  A constant, so that no detail
#: string can differ between the four ways to be refused.
NOT_VISIBLE = "no case is visible here"


@dataclass(frozen=True, slots=True)
class DisclosureRejection:
    failure: DisclosureFailure
    detail: str


def get_my_view(
    service: DisclosureService,
    *,
    tenant_id: str,
    principal: Principal,
    case_id: str,
    context: DisclosureContext,
    acting_as: str | None,
) -> Result[View, DisclosureRejection]:
    """The view this principal is entitled to, derived rather than requested."""
    with service.commitment.casework.database.reading(tenant_id) as scope:
        snapshot = read_published(
            scope,
            case_id,
            service.commitment.casework.publisher_verifier,
            service.commitment.casework.officer_verifier,
            service.commitment.casework.source_verifier,
        )
    if isinstance(snapshot, Err):
        return Err(DisclosureRejection(DisclosureFailure.CASE_NOT_VISIBLE, NOT_VISIBLE))

    audience = resolve_audience(
        principal,
        construction=snapshot.value.construction,
        directory=service.directory,
        acting_as=acting_as,
    )
    if isinstance(audience, Err):
        return Err(_from_audience(audience.error))

    committed = read_commitment(service.commitment, tenant_id=tenant_id, case_id=case_id)
    if isinstance(committed, Err):
        return Err(_from_commitment(committed.error))
    case = committed.value

    entry = resolve_entry(
        case.bundle.disclosure_policy,
        outcome=case.record.certificate.kernel.outcome,
        audience_class=audience.value.value,
        disclosure_context=context.value,
    )
    if isinstance(entry, Err):
        return Err(_from_policy(entry.error))

    return Ok(
        build_view(case.commitment, entry=entry.value, audience=audience.value, context=context)
    )


def _from_audience(error: AudienceRejection) -> DisclosureRejection:
    #  Every audience refusal collapses to the same answer, including the two
    #  that are facts about the caller's own roles: telling a caller "you hold
    #  two roles and named neither" still tells them the case exists.
    _ = error
    return DisclosureRejection(DisclosureFailure.CASE_NOT_VISIBLE, NOT_VISIBLE)


def _from_commitment(error: CommitmentRejection) -> DisclosureRejection:
    return DisclosureRejection(
        DisclosureFailure.COMMITMENT_REFUSED, f"{error.failure.value}: {error.detail}"
    )


def _from_policy(error: PolicyError) -> DisclosureRejection:
    return DisclosureRejection(
        DisclosureFailure.NOT_DISCLOSABLE, f"{error.failure.value}: {error.detail}"
    )
