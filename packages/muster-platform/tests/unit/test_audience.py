"""Audience derivation [G4]: the caller cannot name its own.

The structural half of this is the strongest evidence and it is checked first:
``get_my_view`` has **no** ``audience_class`` parameter, so the dangerous state
is unrepresentable rather than rejected.  A future handler cannot reintroduce
it by reading a field that "was already there", because there is no field.

The rest is the resolution rule.  Roles come from the signed construction
record and the operator directory, a principal holding two roles has to declare
one, and a principal holding none gets the same answer as somebody asking about
a case that does not exist -- because whether a case exists is a disclosure in
its own right.
"""

from __future__ import annotations

import inspect

import pytest

from muster.core.results import Err, Ok
from muster.platform.disclose.audience import (
    AUDITOR,
    AudienceFailure,
    Principal,
    PrincipalDirectory,
    resolve_audience,
    roles_of,
)
from muster.platform.disclose.queries import get_my_view
from support.commitment import (
    AUDITOR_PRINCIPAL,
    EMPLOYER,
    PARTY_ISSUER,
    SITE,
    STRANGER,
    WORKER,
    CommittedFixture,
    committed_case,
    directory_for,
)

TENANT = "tenant-audience"
CASE = "case-audience"

#: The suite's identity configuration, authoritative for this tenant only.
DIRECTORY = directory_for(TENANT)


@pytest.fixture(scope="module")
def fixture() -> CommittedFixture:
    return committed_case(tenant_id=TENANT, case_id=CASE)


def test_the_view_query_has_no_audience_parameter() -> None:
    """The control, stated as a fact about the signature rather than a rule.

    A view built for the wrong audience is internally perfect -- every leaf
    proves, the root matches, the envelope verifies -- so a parameter that
    could name one is a parameter that could hand a participant somebody
    else's disclosure with every downstream check passing.
    """
    parameters = set(inspect.signature(get_my_view).parameters)
    assert "audience_class" not in parameters
    assert "audience" not in parameters
    assert "principal" in parameters
    #  What a caller *may* say is which of their own roles they are acting as.
    assert "acting_as" in parameters


def test_a_party_holds_the_role_the_construction_record_signed(
    fixture: CommittedFixture,
) -> None:
    construction = fixture.case.construction
    assert roles_of(WORKER, construction=construction, directory=DIRECTORY) == frozenset({"WORKER"})
    assert roles_of(EMPLOYER, construction=construction, directory=DIRECTORY) == frozenset(
        {"EMPLOYER"}
    )
    assert roles_of(SITE, construction=construction, directory=DIRECTORY) == frozenset({"SITE"})


def test_the_auditor_role_comes_from_the_directory_and_not_from_the_case(
    fixture: CommittedFixture,
) -> None:
    construction = fixture.case.construction
    assert roles_of(AUDITOR_PRINCIPAL, construction=construction, directory=DIRECTORY) == frozenset(
        {AUDITOR}
    )
    #  And an empty directory means nobody is an auditor, rather than everybody.
    assert (
        roles_of(
            AUDITOR_PRINCIPAL,
            construction=construction,
            directory=PrincipalDirectory(party_issuers={TENANT: PARTY_ISSUER}, auditors={}),
        )
        == frozenset()
    )


def test_a_principal_from_another_issuer_inherits_nothing(fixture: CommittedFixture) -> None:
    """``SITE-A`` from the console and ``SITE-A`` from elsewhere are two subjects."""
    impostor = Principal("some-other-idp", "SITE-A")
    assert roles_of(impostor, construction=fixture.case.construction, directory=DIRECTORY) == (
        frozenset()
    )


def test_a_party_record_naming_another_tenant_is_not_this_case_s_party(
    fixture: CommittedFixture,
) -> None:
    from dataclasses import replace

    construction = fixture.case.construction
    elsewhere = replace(
        construction,
        parties=tuple(replace(party, tenant_id="OTHER") for party in construction.parties),
    )
    assert roles_of(WORKER, construction=elsewhere, directory=DIRECTORY) == frozenset()


def test_a_stranger_gets_the_same_answer_as_an_unknown_case(
    fixture: CommittedFixture,
) -> None:
    result = resolve_audience(
        STRANGER,
        construction=fixture.case.construction,
        directory=DIRECTORY,
        acting_as=None,
    )
    assert isinstance(result, Err)
    assert result.error.failure is AudienceFailure.CASE_NOT_VISIBLE


def test_a_single_role_resolves_without_a_declaration(fixture: CommittedFixture) -> None:
    result = resolve_audience(
        WORKER, construction=fixture.case.construction, directory=DIRECTORY, acting_as=None
    )
    assert isinstance(result, Ok)
    assert result.value.value == "WORKER"


def test_two_roles_must_be_declared_and_are_never_resolved_by_permissiveness(
    fixture: CommittedFixture,
) -> None:
    """ "Most permissive wins" is how an auditor view leaks to a participant."""
    construction = fixture.case.construction
    both = PrincipalDirectory(
        party_issuers={TENANT: PARTY_ISSUER}, auditors={TENANT: frozenset({WORKER})}
    )
    assert roles_of(WORKER, construction=construction, directory=both) == frozenset(
        {"WORKER", AUDITOR}
    )

    undeclared = resolve_audience(WORKER, construction=construction, directory=both, acting_as=None)
    assert isinstance(undeclared, Err)
    assert undeclared.error.failure is AudienceFailure.ROLE_NOT_DECLARED

    for named in ("WORKER", AUDITOR):
        declared = resolve_audience(
            WORKER, construction=construction, directory=both, acting_as=named
        )
        assert isinstance(declared, Ok)
        assert declared.value.value == named


def test_declaring_a_role_you_do_not_hold_is_refused(fixture: CommittedFixture) -> None:
    """The escalation the declaration mechanism would otherwise create."""
    result = resolve_audience(
        WORKER,
        construction=fixture.case.construction,
        directory=DIRECTORY,
        acting_as=AUDITOR,
    )
    assert isinstance(result, Err)
    assert result.error.failure is AudienceFailure.ROLE_NOT_HELD


def test_a_declaration_narrows_and_never_widens(fixture: CommittedFixture) -> None:
    for principal, forbidden in ((EMPLOYER, "WORKER"), (SITE, "EMPLOYER"), (WORKER, "SITE")):
        result = resolve_audience(
            principal,
            construction=fixture.case.construction,
            directory=DIRECTORY,
            acting_as=forbidden,
        )
        assert isinstance(result, Err)
        assert result.error.failure is AudienceFailure.ROLE_NOT_HELD
