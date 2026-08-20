"""``rebuild`` -- a case revision is derived, never authored.

A pure function of the eight ``RebuildInputs`` fields against an immutable
store.  Nothing here reads a clock, an environment variable or the previous
revision: ``as_of`` and ``mode`` are inputs precisely because they change the
answer, and everything else that could is refused entry.

The order of the pass is fixed, and the order is what makes it deterministic:

1. admissibility interprets the transcript -- attested relations become facts or
   constraints, claims become recorded non-effects;
2. the pinned bundle's entailment rules materialise over *those* facts, so a
   normative conclusion is either derived or left open;
3. the declared domain of every variable that is still open is restated as a
   structural constraint.

Step 3 runs last on purpose.  A domain constraint on a variable whose value is
already established is vacuous, and computing it before the facts are settled
would make the revision depend on the order the rules happened to run in.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from muster.admissibility.derive import (
    AdmissibilitySnapshot,
    derive,
    structural_domain_bounds,
)
from muster.core.authority.check import AuthorityView
from muster.core.authority.grants import AuthorityRegistrySnapshot
from muster.core.authority.revocation import RevocationSnapshot
from muster.core.case.revision import (
    Authorizability,
    AuthorizationContext,
    CaseRevision,
    RebuildInputs,
    RebuildMode,
    TranscriptPrefix,
    canonical_constraints,
    canonical_declared,
    canonical_facts,
    canonical_non_effects,
)
from muster.core.evidence.requests import EvidenceRequest
from muster.core.evidence.solicitation import SolicitationView
from muster.core.evidence.transcript import CaseConstructionRecord, TranscriptEntry, entry_digest
from muster.core.results import Err, Ok, Result
from muster.core.wire.digests import Digest
from muster.policy.manifest import LoadedBundle
from muster.policy.materialise import materialise


class RebuildFailure(Enum):
    AUTHORIZATION_CONTEXT_DIGEST_MISMATCH = "AUTHORIZATION_CONTEXT_DIGEST_MISMATCH"
    AUTHORIZATION_CONTEXT_NOT_VALID = "AUTHORIZATION_CONTEXT_NOT_VALID"
    #  The authority snapshot handed to this rebuild is not the one the
    #  revision pinned.  Fatal rather than a non-effect: every authority
    #  decision in the pass would be made against the wrong registry, so there
    #  is no partial answer to give.
    AUTHORITY_SNAPSHOT_NOT_BOUND = "AUTHORITY_SNAPSHOT_NOT_BOUND"
    REVOCATION_SNAPSHOT_NOT_BOUND = "REVOCATION_SNAPSHOT_NOT_BOUND"
    #  Authority state carrying another tenant's name, or another policy
    #  version than the context pinned.
    AUTHORITY_SNAPSHOT_TENANT_MISMATCH = "AUTHORITY_SNAPSHOT_TENANT_MISMATCH"
    AUTHORITY_POLICY_VERSION_MISMATCH = "AUTHORITY_POLICY_VERSION_MISMATCH"
    DUPLICATE_CONSTRAINT_LABEL = "DUPLICATE_CONSTRAINT_LABEL"
    DUPLICATE_ESTABLISHED_REF = "DUPLICATE_ESTABLISHED_REF"
    CONSTRUCTION_DIGEST_MISMATCH = "CONSTRUCTION_DIGEST_MISMATCH"
    TRANSCRIPT_DIGEST_MISMATCH = "TRANSCRIPT_DIGEST_MISMATCH"
    BUNDLE_DIGEST_MISMATCH = "BUNDLE_DIGEST_MISMATCH"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    CASE_MISMATCH = "CASE_MISMATCH"
    POLICY_NOT_EFFECTIVE = "PolicyNotEffective"
    ADMISSIBILITY_FAILED = "ADMISSIBILITY_FAILED"
    ENTAILMENT_FAILED = "ENTAILMENT_FAILED"


@dataclass(frozen=True, slots=True)
class RebuildError:
    failure: RebuildFailure
    detail: str


def rebuild(
    inputs: RebuildInputs,
    construction: CaseConstructionRecord,
    entries: tuple[TranscriptEntry, ...],
    bundle: LoadedBundle,
    authorization_context: AuthorizationContext,
    authority_snapshot: AuthorityRegistrySnapshot,
    revocation_snapshot: RevocationSnapshot,
    solicitations: tuple[EvidenceRequest, ...],
) -> Result[CaseRevision, RebuildError]:
    """Derive the revision named by these inputs, or say why it cannot exist.

    The two authority snapshots are arguments rather than something this
    function looks up, for the same reason the bundle and the construction
    record are: ``rebuild`` reads no store, no clock and no registry handle.
    They are still not *free* inputs -- each must hash to the digest the
    revision's own authorization context pinned, checked below -- so handing in
    a newer, broader or another case's snapshot is refused rather than
    silently honoured.  That check is the whole of snapshot-substitution
    resistance, and it is three lines because the pin is inside the digest.

    ``solicitations`` carries the evidence requests this case issued, and it is
    an argument for the same reason the snapshots are: a rebuild reads no
    store.  It is not a free input either -- each request is re-keyed by its own
    digest and filtered to this tenant and case before anything reads it, so a
    caller cannot file one request under another's identifier or lend one case's
    solicitation to another.  It carries the second half of Q-12(a):
    ``muster.core.evidence.solicitation`` states exactly what it can and cannot
    establish, and why the unevadable half of the same clause belongs at
    admission instead.

    It has **no default**, and that is the same decision ``AdmissionAuthority``
    makes one layer up.  An empty tuple is a legitimate value -- a case that has
    issued no requests has none to resolve against, and every receipt in it is
    volunteered -- but it has to be *passed*, because a defaulted argument would
    make "rebuild without the clause" something a caller could spell by
    forgetting, and every caller that forgot would silently get the weaker of
    two answers.  Empty must be a decision, not an omission.
    """
    if construction.digest() != inputs.construction_digest:
        return Err(RebuildError(RebuildFailure.CONSTRUCTION_DIGEST_MISMATCH, str(inputs.case_id)))
    if bundle.digest() != inputs.bundle_manifest_digest:
        return Err(RebuildError(RebuildFailure.BUNDLE_DIGEST_MISMATCH, str(bundle.digest())))
    if construction.tenant_id != inputs.tenant_id:
        return Err(RebuildError(RebuildFailure.TENANT_MISMATCH, construction.tenant_id))
    if construction.case_id != inputs.case_id:
        return Err(RebuildError(RebuildFailure.CASE_MISMATCH, construction.case_id))
    if authorization_context.digest() != inputs.authorization_context_digest:
        return Err(
            RebuildError(
                RebuildFailure.AUTHORIZATION_CONTEXT_DIGEST_MISMATCH,
                authorization_context.digest().hex,
            )
        )
    if authority_snapshot.digest() != authorization_context.authority_registry_snapshot_digest:
        #  Snapshot substitution, in every form it can take: a newer snapshot,
        #  another case's snapshot, another tenant's snapshot, or a snapshot
        #  edited after publication.  All of them change the digest, and the
        #  digest is pinned inside the revision.
        return Err(
            RebuildError(
                RebuildFailure.AUTHORITY_SNAPSHOT_NOT_BOUND, authority_snapshot.digest().hex
            )
        )
    if revocation_snapshot.digest() != authorization_context.revocation_snapshot_digest:
        return Err(
            RebuildError(
                RebuildFailure.REVOCATION_SNAPSHOT_NOT_BOUND, revocation_snapshot.digest().hex
            )
        )
    if (
        authority_snapshot.tenant_id != inputs.tenant_id
        or revocation_snapshot.tenant_id != inputs.tenant_id
    ):
        #  Belt as well as braces: the digests above already bind the snapshots
        #  to this revision, so reaching here means a case pinned authority
        #  state that names another tenant -- which is a publication defect,
        #  not an attack the pin missed, and it must not be rebuilt from.
        return Err(
            RebuildError(
                RebuildFailure.AUTHORITY_SNAPSHOT_TENANT_MISMATCH, authority_snapshot.tenant_id
            )
        )
    if (
        authority_snapshot.authorization_policy_version
        != authorization_context.authorization_policy_version
    ):
        return Err(
            RebuildError(
                RebuildFailure.AUTHORITY_POLICY_VERSION_MISMATCH,
                str(authority_snapshot.authorization_policy_version),
            )
        )
    if not authorization_context.context_validity.contains(inputs.as_of):
        #  The pinned authority state has to be valid at the instant the case is
        #  being decided as of. Deciding under an authority snapshot that had
        #  already lapsed is the same class of error as admitting an expired
        #  receipt, one level up.
        return Err(RebuildError(RebuildFailure.AUTHORIZATION_CONTEXT_NOT_VALID, str(inputs.as_of)))

    prefix = transcript_prefix(inputs.tenant_id, inputs.case_id, entries)
    if prefix.digest() != inputs.transcript_prefix_digest:
        return Err(RebuildError(RebuildFailure.TRANSCRIPT_DIGEST_MISMATCH, prefix.digest().hex))

    #  Effectivity is where the two modes genuinely differ: a counterfactual
    #  rebuild may look at a bundle outside its window, and the revision it
    #  produces says out loud that it can never authorize anything.
    effective = bundle.is_effective_at(inputs.as_of)
    if not effective and inputs.mode is RebuildMode.OPERATIONAL:
        return Err(RebuildError(RebuildFailure.POLICY_NOT_EFFECTIVE, bundle.manifest.policy_id))
    authorizability = (
        Authorizability.AUTHORIZABLE
        if inputs.mode is RebuildMode.OPERATIONAL
        else Authorizability.NEVER_AUTHORIZABLE
    )

    declared = canonical_declared(construction.declared_instances)
    schema_digest = bundle.predicate_schema.digest()

    admitted = derive(
        AdmissibilitySnapshot(
            inputs.tenant_id, inputs.case_id, inputs.as_of, declared, _ordered(entries)
        ),
        bundle.admissibility_descriptors,
        bundle.predicate_schema,
        schema_digest,
        AuthorityView(
            snapshot=authority_snapshot,
            revocation=revocation_snapshot,
            tenant_id=inputs.tenant_id,
            authorization_policy_version=authorization_context.authorization_policy_version,
            #  The case's own coordinates, read from the record an officer
            #  signed -- never from a receipt, which is the point of Q-12(d).
            case_scope_coordinates=construction.case_scope_coordinates,
            as_of=inputs.as_of,
        ),
        SolicitationView.of(inputs.tenant_id, inputs.case_id, solicitations),
    )
    if isinstance(admitted, Err):
        return Err(RebuildError(RebuildFailure.ADMISSIBILITY_FAILED, str(admitted.error)))

    attested = admitted.value.facts
    entailed = materialise(
        rules=bundle.entailment_rules,
        declared=declared,
        known={fact.ref: fact.value for fact in attested},
        known_facts={fact.ref: fact for fact in attested},
        schema=bundle.predicate_schema,
        manifest_digest=inputs.bundle_manifest_digest,
    )
    if isinstance(entailed, Err):
        return Err(RebuildError(RebuildFailure.ENTAILMENT_FAILED, str(entailed.error)))

    established = canonical_facts(attested + entailed.value.facts)
    settled = {fact.ref for fact in established}
    still_open = tuple(ref for ref in declared if ref not in settled)

    constraints = canonical_constraints(
        admitted.value.constraints
        + entailed.value.constraints
        + structural_domain_bounds(still_open, bundle.predicate_schema, schema_digest)
    )

    #  The revision refuses a duplicate key on construction, and rightly: two
    #  members mapping to one key is how a commitment ends up binding less than
    #  the whole record. But that refusal is an exception, and `rebuild` is on
    #  the public path, so the same condition is reported here as a value.
    duplicate = _first_duplicate(constraint.label for constraint in constraints)
    if duplicate is not None:
        return Err(RebuildError(RebuildFailure.DUPLICATE_CONSTRAINT_LABEL, duplicate))
    repeated = _first_duplicate(str(fact.ref) for fact in established)
    if repeated is not None:
        return Err(RebuildError(RebuildFailure.DUPLICATE_ESTABLISHED_REF, repeated))

    return Ok(
        CaseRevision(
            tenant_id=inputs.tenant_id,
            case_id=inputs.case_id,
            construction_digest=inputs.construction_digest,
            transcript_prefix_digest=inputs.transcript_prefix_digest,
            bundle_pin=inputs.bundle_manifest_digest,
            as_of=inputs.as_of,
            mode=inputs.mode,
            authorization_context_digest=inputs.authorization_context_digest,
            authorizability=authorizability,
            declared=declared,
            established=established,
            constraints=constraints,
            non_effects=canonical_non_effects(admitted.value.non_effects),
        )
    )


def transcript_prefix(
    tenant_id: str, case_id: str, entries: tuple[TranscriptEntry, ...]
) -> TranscriptPrefix:
    """The evidence set, as ascending entry digests.

    A set, not a log: the same receipt submitted twice is the same member, so
    at-least-once delivery costs nothing and the prefix does not depend on
    arrival order.
    """
    digests = sorted({entry_digest(entry).octets for entry in entries})
    return TranscriptPrefix(tenant_id, case_id, tuple(Digest(octets) for octets in digests))


def _first_duplicate(keys: Iterable[str]) -> str | None:
    seen: set[str] = set()
    for key in keys:
        if key in seen:
            return key
        seen.add(key)
    return None


def _ordered(entries: tuple[TranscriptEntry, ...]) -> tuple[TranscriptEntry, ...]:
    return tuple(sorted(entries, key=lambda entry: entry_digest(entry).octets))
