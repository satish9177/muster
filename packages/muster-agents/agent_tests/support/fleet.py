"""The worked fleet: three agents, their material, and the wire between them.

Composed here rather than in each test, because the composition *is* part of
what the milestone claims: three identities, three key populations, two
evidence stores the control plane cannot reach, one catalog that says where
each one is, and one transport that carries octets and nothing else.

The identities deliberately match the ones the control-plane suite already
publishes grants and profiles for.  A fleet whose agents held keys the authority
registry had never heard of would produce receipts that fail Q-12(b) -- which is
correct behaviour and a confusing way to discover that a fixture is wrong.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from google.adk.models.base_llm import BaseLlm

from agent_tests.support.interpreters import Reading, RuleBasedClaimant, RuleBasedInterpreter
from muster.agents.common.environment import FixedClock, SequenceNonce
from muster.agents.common.identity import SourceIdentity
from muster.agents.keys import LocalSourceSigner
from muster.agents.profiles import (
    HR_PAYROLL_SYSTEM,
    SITE_ACCESS_CONTROL,
    employer_agent,
    site_agent,
    worker_agent,
)
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.runtime.claimant import ClaimAgent
from muster.agents.runtime.claims import ClaimBrief, ClaimTarget
from muster.agents.runtime.interpret import InterpreterLimits
from muster.agents.runtime.receipts import AttestationPolicy
from muster.agents.sources.local import LocalDirectoryEvidenceStore
from muster.agents.transport.inprocess import InProcessAcquisitionTransport
from muster.core.authority.scope import ResourceScope
from muster.core.evidence.transcript import Statement, TranscriptEntry
from muster.core.values.sorts import BoolDomain, BoolSort
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Duration, Instant
from support.authority import PAYROLL_KEY, SITE_A_KEY, WORKER_KEY, source_signer
from support.ravi import ACQUIRED_BY_THE_FLEET, SATURDAY, RaviCase, without

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SITE_MATERIAL = FIXTURES / "site-a"
EMPLOYER_MATERIAL = FIXTURES / "employer-1"
WORKER_ACCOUNT = (FIXTURES / "worker" / "ravi-account.txt").read_text(encoding="utf-8")

SITE_AGENT_ID = "agent-site-a"
EMPLOYER_AGENT_ID = "agent-hr-payroll"
SITE_ENDPOINT = f"local://{SITE_AGENT_ID}"
EMPLOYER_ENDPOINT = f"local://{EMPLOYER_AGENT_ID}"

SITE = "SITE-A"
EMPLOYER = "EMPLOYER-1"
WORKER = "RAVI"

#: Re-exported from the case fixture, not restated here.  What the fleet is
#: asked for and how the worked transcript is shaped are statements about the
#: *case*, and the cloud composition root reads them without an agent package
#: on its path -- so they have one home, and it is not this file.
__all__ = ("ACQUIRED_BY_THE_FLEET", "SATURDAY", "without")

#  The key each source signs under, named here as well as in the control
#  plane's own fixtures.  A test about the fleet should read the fleet's key
#  reference from the fleet, rather than reaching past it -- and if the two
#  ever disagree, every receipt the suite produces stops verifying, loudly.
SITE_KEY_REF = SITE_A_KEY
EMPLOYER_KEY_REF = PAYROLL_KEY
WORKER_KEY_REF = WORKER_KEY

#  The instant these sources issue their attestations at.  Fixed rather than
#  read, for the reason every clock in MUSTER is supplied: the worked case is
#  pinned to an ``as_of`` that is not today, a receipt is admissible only
#  inside a window containing that instant, and a fixture that read the wall
#  clock would mint receipts that verify, admit, and do nothing.
ISSUED_AT: Instant = 1_785_996_400_000_000

#  The Saturday under dispute, as the site's own material timestamps it.
OBSERVED_AT = "2026-08-01T09:12:00+00:00"

#  A day.  Long enough that a source issuing on the Thursday still covers the
#  case's instant, short enough to be a real expiry rather than a formality.
VALIDITY_TTL = Duration(24 * 3_600 * 1_000_000)

#  Thirty days.  The worked case is a Saturday reported on the following
#  Thursday, so the horizon has to be a length that covers ordinary
#  reporting delay -- which is the whole reason it is not the validity
#  window applied backwards.
OBSERVATION_HORIZON = Duration(30 * 24 * 3_600 * 1_000_000)

LIMITS = InterpreterLimits(max_model_calls=12, timeout_seconds=30.0)
POLICY = AttestationPolicy(validity_ttl=VALIDITY_TTL, observation_horizon=OBSERVATION_HORIZON)


def site_identity(tenant_id: str, *, site: str = SITE, key_ref: str = SITE_A_KEY) -> SourceIdentity:
    return SourceIdentity(
        agent_id=SITE_AGENT_ID,
        principal_id=site,
        tenant_id=tenant_id,
        source_class=SITE_ACCESS_CONTROL,
        key_ref=key_ref,
        acquirable_predicates=("on_site_duration", "present_on_site"),
        resource_scope=(ResourceScope("SITE", site),),
    )


def employer_identity(tenant_id: str) -> SourceIdentity:
    return SourceIdentity(
        agent_id=EMPLOYER_AGENT_ID,
        principal_id=EMPLOYER,
        tenant_id=tenant_id,
        source_class=HR_PAYROLL_SYSTEM,
        key_ref=PAYROLL_KEY,
        acquirable_predicates=("daily_rate", "scheduled"),
        resource_scope=(ResourceScope("EMPLOYER", EMPLOYER),),
    )


def signer(key_ref: str) -> LocalSourceSigner:
    """The agent's own signer, over the key material the suite's keyring holds.

    Built from ``muster.agents.keys`` rather than from the control plane's
    crypto adapter, deliberately: a source key lives with the source, and a
    fixture that reached across to the control plane's signer would be quietly
    testing that the two distributions share an implementation rather than a
    contract.  They share the contract -- the algorithm identifier and the
    covered octets -- and this is where that is exercised.
    """
    return LocalSourceSigner(key_ref, source_signer(key_ref).private_key_pem)


def site_reader() -> RuleBasedInterpreter:
    """A competent badge-and-camera interpreter, deterministically.

    Presence from the attendance board, exactly; duration from the gate log, as
    a **lower bound**.  The bound is the interesting reading and it is the
    honest one: the log shows an entry and an exit, and the policy asks whether
    four hours were worked, not how many.
    """
    return RuleBasedInterpreter(
        model="rule-based-site-interpreter",
        readings={
            "present_on_site": Reading("exact", "true", OBSERVED_AT, prefer_media=True),
            "on_site_duration": Reading("at_least", "240", OBSERVED_AT),
        },
    )


def employer_reader() -> RuleBasedInterpreter:
    """A payroll-export interpreter: the roster says Saturday was rostered."""
    return RuleBasedInterpreter(
        model="rule-based-payroll-interpreter",
        readings={
            "scheduled": Reading("exact", "true", OBSERVED_AT),
            "daily_rate": Reading("exact", "850.00", OBSERVED_AT),
        },
    )


def worker_reader() -> RuleBasedClaimant:
    """What Ravi's message amounts to: he says he was there on the Saturday."""
    return RuleBasedClaimant(model="rule-based-claim-intake", claims={"present_on_site": "true"})


def site(
    tenant_id: str,
    *,
    model: BaseLlm | None = None,
    identity: SourceIdentity | None = None,
    material: Path | None = None,
    limits: InterpreterLimits | None = None,
) -> AcquisitionAgent:
    resolved = identity if identity is not None else site_identity(tenant_id)
    return site_agent(
        identity=resolved,
        store=LocalDirectoryEvidenceStore(material if material is not None else SITE_MATERIAL),
        model=model if model is not None else site_reader(),
        signer=signer(resolved.key_ref),
        clock=FixedClock(ISSUED_AT),
        nonces=SequenceNonce(),
        limits=limits if limits is not None else LIMITS,
        policy=POLICY,
    )


def employer(
    tenant_id: str,
    *,
    model: BaseLlm | None = None,
    material: Path | None = None,
    limits: InterpreterLimits | None = None,
) -> AcquisitionAgent:
    identity = employer_identity(tenant_id)
    return employer_agent(
        identity=identity,
        store=LocalDirectoryEvidenceStore(material if material is not None else EMPLOYER_MATERIAL),
        model=model if model is not None else employer_reader(),
        signer=signer(identity.key_ref),
        clock=FixedClock(ISSUED_AT),
        nonces=SequenceNonce(),
        limits=limits if limits is not None else LIMITS,
        policy=POLICY,
    )


def worker(*, model: BaseLlm | None = None, limits: InterpreterLimits | None = None) -> ClaimAgent:
    return worker_agent(
        model=model if model is not None else worker_reader(),
        clock=FixedClock(ISSUED_AT),
        limits=limits if limits is not None else LIMITS,
    )


def transport(agents: Mapping[str, AcquisitionAgent]) -> InProcessAcquisitionTransport:
    return InProcessAcquisitionTransport(agents)


def whole_fleet(tenant_id: str) -> InProcessAcquisitionTransport:
    """Both acquisition agents, at the endpoints the published catalog names."""
    return transport({SITE_ENDPOINT: site(tenant_id), EMPLOYER_ENDPOINT: employer(tenant_id)})


def worker_brief(tenant_id: str, case_id: str) -> ClaimBrief:
    """What Ravi may say something about.

    One target, and it is the *observation* predicate rather than the normative
    one -- because the normative predicate is DERIVED and there is no brief,
    tool or argument anywhere that could offer it.  Ravi cannot claim his shift
    is payable; the schema does not have a way to say it.
    """
    return ClaimBrief(
        tenant_id=tenant_id,
        case_id=case_id,
        claimant=WORKER,
        role_in_case="WORKER",
        signer_key_ref=WORKER_KEY,
        targets=(
            ClaimTarget(
                proposition=SymbolRef("present_on_site", (WORKER, SATURDAY)),
                value_sort=BoolSort(),
                domain=BoolDomain(),
                description="whether you were on site on the Saturday",
            ),
        ),
    )


#  ---- shaping the worked transcript --------------------------------------


def only_statements(case: RaviCase) -> tuple[TranscriptEntry, ...]:
    return tuple(entry for entry in case.entries if isinstance(entry, Statement))
