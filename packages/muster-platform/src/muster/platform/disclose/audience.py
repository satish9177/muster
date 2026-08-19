"""Where an audience class comes from, and where it emphatically does not.

The rule the whole privacy claim rests on is that **a caller cannot name its
own audience**.  A view built for the wrong audience is internally perfect --
every leaf proves membership, the root matches, the envelope signature
verifies -- because redaction was the writer's job and the writer did it
correctly, for somebody else.  Nothing downstream can detect that.  So the
audience has to be derived from a verified identity before any of it starts:

    audience  =  AUDITOR                       if the operator directory says so
              |  parties[principal].role       if the caller is a recorded party
              |  nothing

and the query that produces a view takes a principal, never an audience.

**Multi-role principals resolve by declaration, never by permissiveness.**  A
principal who is both a recorded party and a directory auditor has to say which
role they are acting as, and is refused if it is not one of theirs.  "Most
permissive wins" is exactly how an auditor view reaches a participant.

**An unresolvable principal is not distinguishable from an unknown case.**
Whether a case exists is itself a disclosure, so the failure carries one value
for both, and a caller learns nothing by asking about cases they are not party
to.

The **pure** layer below this takes an already-resolved :class:`AudienceClass`
as an ordinary argument, which is correct and is not a hole: by then the
resolution has happened and the value is a conclusion rather than a request.
The hole would be an imperative entry point that accepted one, and there is not
one.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from muster.core.evidence.transcript import CaseConstructionRecord
from muster.core.results import Err, Ok, Result

#: The one audience class that is not a party to the case.  It is structurally
#: different from every other -- resolved from the operator directory rather
#: than from the signed construction record -- and that difference, not a
#: branch on the name, is why an auditor receives a differently-shaped view.
AUDITOR = "AUDITOR"

#: Role names a case may not name a party with.  A closed set of one today,
#: and a set rather than a constant because the rule is "a case cannot mint an
#: operator role", not "a case cannot say AUDITOR".
OPERATOR_ROLES = frozenset({AUDITOR})


@dataclass(frozen=True, slots=True)
class AudienceClass:
    """A resolved audience.  Nominal, so a bare string cannot stand in for one.

    The value is whatever the bundle's disclosure policy and the case's
    construction record agree to call a role.  It is not an enumeration here
    because the set is bundle data: a workforce case has a worker, an employer
    and a site, a procurement case has a supplier and a warehouse, and the code
    that resolves and applies them is identical for both.
    """

    value: str


@dataclass(frozen=True, slots=True)
class DisclosureContext:
    """Why a view is being produced.  Bundle data, exactly like the audience."""

    value: str


@dataclass(frozen=True, slots=True)
class Principal:
    """A caller, as an identity layer verified it -- never as a body claimed it.

    Two fields because one is not enough to be a subject: ``SITE-A`` issued by
    the operator directory and ``SITE-A`` issued by a tenant's own identity
    provider are different principals, and collapsing them would let the second
    inherit the first's roles.
    """

    issuer: str
    subject: str


@dataclass(frozen=True, slots=True)
class PrincipalDirectory:
    """Who a principal is, for the two questions a case cannot answer itself.

    A ``CaseConstructionRecord`` names its parties by ``principal_id`` and
    nothing else -- it is a frozen wire type and it carries no issuer, and no
    tenant of its own that a caller did not choose -- so something has to say
    **which issuer's subjects those identifiers name, for which tenant**.

    Both halves are load-bearing and each closes a different escalation.
    Without the issuer, ``SITE-A`` minted by any identity provider a deployment
    happens to accept resolves to the site's role.  Without the *per-tenant*
    part, a subject authoritative in one tenant resolves to the party of the
    same name in another: the tenant a query names is a caller's argument, and
    the tenant on a party record is stamped from that same argument when the
    record is read, so comparing the two proves nothing.  A deployment that
    genuinely shares one issuer across tenants writes the same value twice and
    thereby says so, rather than getting the weaker rule by default.

    ``auditors`` is the second question: an operator role is not a role in any
    case, so it cannot come from the construction record at all.  Its members
    are whole principals, issuer included, because there is nothing here for
    them to inherit an issuer from -- and they are keyed by tenant for the same
    reason the issuers are.  A flat set would make the *widest* audience in the
    system the one role granted globally: a directory scoped to one tenant
    would resolve its auditors inside every other tenant the deployment serves,
    and the reader-side tenant check would not object, because the reader and
    the envelope would agree on the wrong tenant.  A deployment with genuinely
    cross-tenant auditors lists the principal once per tenant and thereby says
    so.

    A value rather than a lookup port, because a directory that could fail at
    resolution time is a directory that decides who is an auditor by whether a
    query timed out.
    """

    party_issuers: Mapping[str, str]
    auditors: Mapping[str, frozenset[Principal]]

    def issuer_for(self, tenant_id: str) -> str | None:
        """Which issuer's subjects this tenant's party identifiers name."""
        return self.party_issuers.get(tenant_id)

    def auditors_for(self, tenant_id: str) -> frozenset[Principal]:
        """The operator principals holding the auditor role *in this tenant*."""
        return self.auditors.get(tenant_id, frozenset())


class AudienceFailure(Enum):
    #: The principal is party to no role in this case and holds no operator
    #: role.  Deliberately the same answer as "no such case": whether a case
    #: exists is a disclosure in its own right.
    CASE_NOT_VISIBLE = "CASE_NOT_VISIBLE"
    #: The principal holds more than one role and named none.  Refused rather
    #: than resolved: any tie-break here is a rule about which disclosure wins,
    #: and the most permissive one always would.
    ROLE_NOT_DECLARED = "ROLE_NOT_DECLARED"
    #: The principal named a role that is not one of theirs.
    ROLE_NOT_HELD = "ROLE_NOT_HELD"


@dataclass(frozen=True, slots=True)
class AudienceRejection:
    failure: AudienceFailure
    detail: str


def roles_of(
    principal: Principal, *, construction: CaseConstructionRecord, directory: PrincipalDirectory
) -> frozenset[str]:
    """Every audience class this principal legitimately holds for this case.

    Party roles come from the signed construction record and never from a
    party's own assertion about itself; the operator role comes from the
    directory.  Three things have to line up for a party role to be held, and
    each one closes a distinct escalation:

    * the **issuer** must be the one this *tenant's* party identifiers are
      minted by, or a token from any other accepted issuer -- including one
      authoritative for a different tenant -- inherits a party's role by
      choosing its subject;
    * the **tenant** on the party record must be the case's, because the record
      is a list rather than a map;
    * the **subject** must match the identifier the officer signed.

    And one name is excluded outright.  An operator role is not a role in any
    case, so a construction record must not be able to mint one: a party whose
    ``role_in_case`` happens to be the operator's name would otherwise receive
    the operator's audience -- the widest one -- granted from inside a case,
    which is the one thing the two-source rule exists to prevent.
    """
    issuer = directory.issuer_for(construction.tenant_id)
    held = {
        party.role_in_case
        for party in construction.parties
        if issuer is not None
        and principal.issuer == issuer
        and party.role_in_case not in OPERATOR_ROLES
        and party.principal_id == principal.subject
        and party.tenant_id == construction.tenant_id
    }
    if principal in directory.auditors_for(construction.tenant_id):
        held.add(AUDITOR)
    return frozenset(held)


def resolve_audience(
    principal: Principal,
    *,
    construction: CaseConstructionRecord,
    directory: PrincipalDirectory,
    acting_as: str | None,
) -> Result[AudienceClass, AudienceRejection]:
    """The caller's audience class for this case, or a typed refusal.

    ``acting_as`` is a *declaration*, not a request: it can only ever narrow a
    set the principal already holds, and naming a role they do not hold is
    refused rather than ignored.  A principal holding exactly one role may omit
    it; a principal holding two must not, because choosing for them is choosing
    which disclosure they get.
    """
    held = roles_of(principal, construction=construction, directory=directory)
    if not held:
        return Err(
            AudienceRejection(
                AudienceFailure.CASE_NOT_VISIBLE,
                f"{principal.issuer}/{principal.subject} holds no role in this case",
            )
        )
    if acting_as is not None:
        if acting_as not in held:
            return Err(
                AudienceRejection(
                    AudienceFailure.ROLE_NOT_HELD,
                    f"{principal.issuer}/{principal.subject} does not hold {acting_as!r}",
                )
            )
        return Ok(AudienceClass(acting_as))
    if len(held) > 1:
        return Err(
            AudienceRejection(
                AudienceFailure.ROLE_NOT_DECLARED,
                f"{principal.issuer}/{principal.subject} holds {sorted(held)} and named none",
            )
        )
    return Ok(AudienceClass(next(iter(held))))
