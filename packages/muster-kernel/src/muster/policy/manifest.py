"""The signed bundle manifest, and the loaded bundle it authenticates.

A version number plus a golden digest is not pinning.  The manifest commits to
*every* semantic artifact and to the interpreter version that reads them, as one
approved tuple, so "the policy changed" cannot mean "the entailment rules
changed and the pin did not notice".

``load_bundle`` recomputes each subartifact digest and refuses any mismatch.
That is what makes ``load_by_digest`` meaningful: replay resolves nothing, it
loads exactly the tuple that was ratified.

**Signatures are carried, not verified.**  Milestone A holds no keyring and is
offline.  ``signature`` travels with the manifest and is covered by the same
octets it will be covered by later; nothing here may be read as evidence that a
policy authority signed anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.actions import ActionSchema
from muster.core.evidence.transcript import Signature
from muster.core.expr.terms import term_digest
from muster.core.results import Err, Ok, Result
from muster.core.values.times import HalfOpenInterval, Instant
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.core.wire.nodes import NAtom, NInt, NRec
from muster.core.wire.shape import atom_or_none, option_node
from muster.policy.artifacts import AdmissibilityDescriptors, DisclosurePolicy, RatificationSet
from muster.policy.entailment import DefinitionRule, EntailmentRules
from muster.policy.predicates import PredicateSchema
from muster.policy.program import DecisionProgram

TAG_BUNDLE_MANIFEST = "BundleManifest/v1"
TAG_SIGNED_MANIFEST = "SignedManifest/v1"


@dataclass(frozen=True, slots=True)
class BundleManifest:
    manifest_schema_version: int
    tenant_scope: str | None
    policy_id: str
    human_version: str
    effective_interval: HalfOpenInterval
    decision_program_digest: Digest
    entailment_rules_digest: Digest
    admissibility_descriptors_digest: Digest
    predicate_schema_digest: Digest
    action_schema_digest: Digest
    disclosure_policy_digest: Digest
    ratification_records_digest: Digest
    ir_schema_version: int
    interpreter_version: int
    ratified_by: str
    ratified_at: Instant
    signer_key_ref: str

    def to_node(self) -> NRec:
        return NRec(
            TAG_BUNDLE_MANIFEST,
            (
                NInt(self.manifest_schema_version),
                option_node(atom_or_none(self.tenant_scope)),
                NAtom(self.policy_id),
                NAtom(self.human_version),
                self.effective_interval.to_node(),
                self.decision_program_digest.to_node(),
                self.entailment_rules_digest.to_node(),
                self.admissibility_descriptors_digest.to_node(),
                self.predicate_schema_digest.to_node(),
                self.action_schema_digest.to_node(),
                self.disclosure_policy_digest.to_node(),
                self.ratification_records_digest.to_node(),
                NInt(self.ir_schema_version),
                NInt(self.interpreter_version),
                NAtom(self.ratified_by),
                NInt(self.ratified_at),
                NAtom(self.signer_key_ref),
            ),
        )

    def digest(self) -> Digest:
        return digest_node(DigestKind.MANIFEST, self.to_node())


@dataclass(frozen=True, slots=True)
class SignedManifest:
    manifest: BundleManifest
    signature: Signature

    def to_node(self) -> NRec:
        return NRec(TAG_SIGNED_MANIFEST, (self.manifest.to_node(), self.signature.to_node()))


class BundleFailure(Enum):
    SUBARTIFACT_DIGEST_MISMATCH = "SUBARTIFACT_DIGEST_MISMATCH"
    UNSUPPORTED_IR_SCHEMA_VERSION = "UNSUPPORTED_IR_SCHEMA_VERSION"
    UNSUPPORTED_INTERPRETER_VERSION = "UNSUPPORTED_INTERPRETER_VERSION"
    RATIFICATION_UNRESOLVED = "RATIFICATION_UNRESOLVED"
    RATIFICATION_SUBJECT_MISMATCH = "RATIFICATION_SUBJECT_MISMATCH"
    MEASUREMENT_PROCEDURE_NOT_ADMITTED = "MEASUREMENT_PROCEDURE_NOT_ADMITTED"


@dataclass(frozen=True, slots=True)
class BundleError:
    failure: BundleFailure
    detail: str


#  Bumped when the wire grammar or the interpreter's semantics change.  A bundle
#  ratified against a different interpreter is refused rather than best-effort
#  interpreted: the whole point of pinning is that the reader is pinned too.
SUPPORTED_IR_SCHEMA_VERSION = 1
SUPPORTED_INTERPRETER_VERSION = 1


@dataclass(frozen=True, slots=True)
class LoadedBundle:
    """A manifest together with the artifacts it commits to, digests verified."""

    signed_manifest: SignedManifest
    program: DecisionProgram
    entailment_rules: EntailmentRules
    predicate_schema: PredicateSchema
    action_schema: ActionSchema
    admissibility_descriptors: AdmissibilityDescriptors
    disclosure_policy: DisclosurePolicy
    ratifications: RatificationSet

    @property
    def manifest(self) -> BundleManifest:
        return self.signed_manifest.manifest

    def digest(self) -> Digest:
        return self.manifest.digest()

    def is_effective_at(self, moment: Instant) -> bool:
        return self.manifest.effective_interval.contains(moment)


def load_bundle(
    *,
    signed_manifest: SignedManifest,
    program: DecisionProgram,
    entailment_rules: EntailmentRules,
    predicate_schema: PredicateSchema,
    action_schema: ActionSchema,
    admissibility_descriptors: AdmissibilityDescriptors,
    disclosure_policy: DisclosurePolicy,
    ratifications: RatificationSet,
) -> Result[LoadedBundle, BundleError]:
    """Admit a bundle only if every artifact is the one the manifest names."""
    manifest = signed_manifest.manifest

    if manifest.ir_schema_version != SUPPORTED_IR_SCHEMA_VERSION:
        return Err(
            BundleError(
                BundleFailure.UNSUPPORTED_IR_SCHEMA_VERSION, str(manifest.ir_schema_version)
            )
        )
    if manifest.interpreter_version != SUPPORTED_INTERPRETER_VERSION:
        return Err(
            BundleError(
                BundleFailure.UNSUPPORTED_INTERPRETER_VERSION, str(manifest.interpreter_version)
            )
        )

    expected: tuple[tuple[str, Digest, Digest], ...] = (
        ("decision_program", manifest.decision_program_digest, program.digest()),
        ("entailment_rules", manifest.entailment_rules_digest, entailment_rules.digest()),
        (
            "admissibility_descriptors",
            manifest.admissibility_descriptors_digest,
            admissibility_descriptors.digest(),
        ),
        ("predicate_schema", manifest.predicate_schema_digest, predicate_schema.digest()),
        ("action_schema", manifest.action_schema_digest, action_schema.digest()),
        ("disclosure_policy", manifest.disclosure_policy_digest, disclosure_policy.digest()),
        ("ratification_records", manifest.ratification_records_digest, ratifications.digest()),
    )
    for name, pinned, actual in expected:
        if pinned != actual:
            return Err(BundleError(BundleFailure.SUBARTIFACT_DIGEST_MISMATCH, name))

    #  A definition rule claims exhaustiveness, and the claim is worth something
    #  only if the ratification it cites is in this same signed tuple *and*
    #  ratifies these exact criteria.  Without the second half, a ratification
    #  signed for one premise could be carried onto a rule whose criteria were
    #  widened afterwards.
    for rule in entailment_rules.rules:
        if not isinstance(rule, DefinitionRule):
            continue
        cited = ratifications.record(rule.exhaustiveness_ratification_ref)
        if cited is None:
            return Err(BundleError(BundleFailure.RATIFICATION_UNRESOLVED, rule.rule_id))
        if cited.subject_ref != term_digest(rule.premise):
            return Err(
                BundleError(
                    BundleFailure.RATIFICATION_SUBJECT_MISMATCH,
                    f"{rule.rule_id} cites {cited.ratification_id}",
                )
            )

    #  Every measurement procedure the predicate schema declares must be one
    #  the admissibility descriptor admits. Otherwise the bundle is internally
    #  inconsistent in the quietest possible way: every receipt for that
    #  predicate is refused, and the case simply never resolves.
    attested = admissibility_descriptors.descriptor("AttestedRelation")
    if attested is not None:
        for spec in predicate_schema.predicates:
            procedure = spec.measurement_class
            if procedure is not None and procedure not in attested.admissible_procedures:
                return Err(
                    BundleError(
                        BundleFailure.MEASUREMENT_PROCEDURE_NOT_ADMITTED,
                        f"{spec.predicate_id}: {procedure}",
                    )
                )

    return Ok(
        LoadedBundle(
            signed_manifest,
            program,
            entailment_rules,
            predicate_schema,
            action_schema,
            admissibility_descriptors,
            disclosure_policy,
            ratifications,
        )
    )
