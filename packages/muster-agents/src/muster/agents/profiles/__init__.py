"""The three agents, as configuration over two runtimes.

    Site Agent      acquisition runtime   SITE_ACCESS_CONTROL   attests OBSERVATION
    Employer Agent  acquisition runtime   HR_PAYROLL_SYSTEM     attests RECORD
    Worker Agent    claim runtime         no source class       attests nothing

Three, and exactly three.  The hinge, the planner, the authority check, the
catalog and the dispatcher are deterministic components and are not promoted to
agents here or anywhere: an agent is a process that holds material or a
credential MUSTER must not hold, and none of those does.

**The site and employer agents share every line of their runtime.**  That is
the claim §24 of the architecture makes about domain independence, and this
module is where it is either true or a slogan: the identity, the key, the
resource scope and the material are configuration, and the runtime that reads
them is one function.  Re-pointing the site profile at a warehouse's
goods-receipt system needs a new resource scope, a new key and a new directory,
and no change to the acquisition runtime at all.

What is **not** pure configuration is the source class, and it is honest to say
so: the two classes are named here, one per factory, and the composition root
picks a factory from the configured class.  A third institutional class is two
small edits -- a constant and a factory -- rather than none.  That is a
deliberate trade: a factory that took the class as an argument would accept any
string, and "an agent presenting a class it was not built as does not start"
would stop being checkable at composition time.

**The worker agent is built by a different function on purpose.**  It takes no
signer and no evidence store, and it returns statements rather than receipts,
because the property that matters about it is an absence: there is no argument,
no branch and no import by which it could produce an attestation.  A single
``build_agent`` with a ``claims_only`` flag would turn that absence into a
boolean, and a boolean is something a later edit can get wrong.
"""

from __future__ import annotations

from google.adk.models.base_llm import BaseLlm

from muster.agents.common.environment import NonceSource, SourceClock
from muster.agents.common.identity import SourceIdentity
from muster.agents.runtime.agent import AcquisitionAgent
from muster.agents.runtime.claimant import ClaimAgent
from muster.agents.runtime.interpret import InterpreterLimits
from muster.agents.runtime.receipts import AttestationPolicy
from muster.agents.sources.ports import SourceEvidenceStore
from muster.core.authority.signing import SourceSigner
from muster.core.results import InvariantViolation

#: The two institutional classes the worked domain declares.  They are *names*
#: here and authority nowhere: a grant binding a key to one of them lives in
#: the signed authority registry, which this package cannot write and does not
#: import.  An agent configured with a class it holds no grant for produces
#: receipts that Q-12(b) refuses, which is the correct and observable outcome.
SITE_ACCESS_CONTROL = "SITE_ACCESS_CONTROL"
HR_PAYROLL_SYSTEM = "HR_PAYROLL_SYSTEM"


def site_agent(
    *,
    identity: SourceIdentity,
    store: SourceEvidenceStore,
    model: BaseLlm,
    signer: SourceSigner,
    clock: SourceClock,
    nonces: NonceSource,
    limits: InterpreterLimits,
    policy: AttestationPolicy,
) -> AcquisitionAgent:
    """The source-local observer: raw site material in, one relation out.

    The strongest of the three, and the only one where the privacy claim and
    the evidential claim are the same claim.  Its material -- an attendance
    photograph, a gate log -- is held where the site holds it, read by an
    identity the control plane does not have, and interpreted in the site's own
    boundary.  What leaves is a proposition and a relation.
    """
    _refuse_mismatch(identity, SITE_ACCESS_CONTROL, signer)
    return _acquisition(
        identity=identity,
        store=store,
        model=model,
        signer=signer,
        clock=clock,
        nonces=nonces,
        limits=limits,
        policy=policy,
    )


def employer_agent(
    *,
    identity: SourceIdentity,
    store: SourceEvidenceStore,
    model: BaseLlm,
    signer: SourceSigner,
    clock: SourceClock,
    nonces: NonceSource,
    limits: InterpreterLimits,
    policy: AttestationPolicy,
) -> AcquisitionAgent:
    """The employer's records, within the employer's own authority.

    It interprets payroll and roster material the employer controls and attests
    at RECORD.  It cannot attest a site observation, and the reason is not that
    this function forbids it: its key holds a grant for ``HR_PAYROLL_SYSTEM``
    and Q-12(b) resolves no grant for anything else, so the receipt would be
    refused at rebuild however it was produced.  What this configuration adds
    is that the attempt is refused *here*, before a signature is spent, and
    reported as the routing fault it is.
    """
    _refuse_mismatch(identity, HR_PAYROLL_SYSTEM, signer)
    return _acquisition(
        identity=identity,
        store=store,
        model=model,
        signer=signer,
        clock=clock,
        nonces=nonces,
        limits=limits,
        policy=policy,
    )


def worker_agent(*, model: BaseLlm, clock: SourceClock, limits: InterpreterLimits) -> ClaimAgent:
    """The worker's own account, turned into a claim that decides nothing.

    Note what it is not given: no signer, no source class, no resource scope
    and no evidence store.  There is nothing here to configure into an
    attestation, which is why the worker's correctness is irrelevant to the
    outcome -- his claim agrees with the site's observation in the worked case,
    and contributes exactly nothing either way.
    """
    return ClaimAgent(model=model, clock=clock, limits=limits)


def _refuse_mismatch(identity: SourceIdentity, expected_class: str, signer: SourceSigner) -> None:
    """Refuse a mis-configured deployment before it accepts any traffic.

    Two checks, both at composition time rather than at request time, because
    both describe a deployment that is wrong before an assignment ever arrives:
    an identity presenting a class the profile is not for, and a signer holding
    a key the identity does not name.  A process that fails to start is
    strictly better than one that starts and produces receipts nobody can use.
    """
    if identity.source_class != expected_class:
        raise InvariantViolation(
            f"{identity.agent_id} presents {identity.source_class!r} "
            f"and was built as a {expected_class} agent"
        )
    if signer.key_ref != identity.key_ref:
        raise InvariantViolation(
            f"{identity.agent_id} names {identity.key_ref!r} and holds a signer "
            f"for {signer.key_ref!r}"
        )


def _acquisition(
    *,
    identity: SourceIdentity,
    store: SourceEvidenceStore,
    model: BaseLlm,
    signer: SourceSigner,
    clock: SourceClock,
    nonces: NonceSource,
    limits: InterpreterLimits,
    policy: AttestationPolicy,
) -> AcquisitionAgent:
    """The eight fields an acquisition agent is, and nothing decided here."""
    return AcquisitionAgent(
        identity=identity,
        store=store,
        model=model,
        signer=signer,
        clock=clock,
        nonces=nonces,
        limits=limits,
        policy=policy,
    )
