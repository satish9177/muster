# MUSTER Phase 0.8 -- declarative schema inventory

NON-PRODUCTION SPECIFICATION MATERIAL.  Generated from `muster_spec/registry.py`.

- types: **143**  (128 records, 14 unions, 1 aliases)
- digest kinds: **55**, all distinct
- signed artifacts: **13**
- commitment paths: **29** inventory entries

## Record tags and arities

| Type | Tag | Arity | Digest kind | Persistence |
|---|---|---|---|---|
| `Signature` | `Signature/v1` | 2 | -- | embedded |
| `HalfOpenInterval` | `HalfOpen/v1` | 2 | -- | embedded |
| `SymbolRef` | `SymbolRef/v1` | 2 | `SYMBOL_REF` | embedded |
| `SymbolRefTemplate` | `SymbolRefTemplate/v1` | 2 | -- | embedded |
| `ScaledSort` | `ScaledSort/v1` | 2 | -- | embedded |
| `EnumSort` | `EnumSort/v1` | 1 | -- | embedded |
| `IntRange` | `IntRange/v1` | 2 | -- | embedded |
| `ScaledRange` | `ScaledRange/v1` | 2 | -- | embedded |
| `EnumDomain` | `EnumDomain/v1` | 1 | -- | embedded |
| `VScaled` | `VScaled/v1` | 3 | -- | embedded |
| `VEnum` | `VEnum/v1` | 2 | -- | embedded |
| `QueryVar` | `QueryVar/v1` | 2 | -- | embedded |
| `Bin` | `Bin/v1` | 2 | -- | embedded |
| `MulConst` | `MulConst/v1` | 2 | -- | embedded |
| `Scale` | `Scale/v1` | 3 | -- | embedded |
| `Rescale` | `Rescale/v1` | 2 | -- | embedded |
| `Ite` | `Ite/v1` | 3 | -- | embedded |
| `Arm` | `Arm/v1` | 2 | -- | embedded |
| `EnumTable` | `EnumTable/v1` | 2 | -- | embedded |
| `QBin` | `QBin/v1` | 2 | -- | embedded |
| `QMulConst` | `QMulConst/v1` | 2 | -- | embedded |
| `QScale` | `QScale/v1` | 3 | -- | embedded |
| `QRescale` | `QRescale/v1` | 2 | -- | embedded |
| `QIte` | `QIte/v1` | 3 | -- | embedded |
| `QArm` | `QArm/v1` | 2 | -- | embedded |
| `QEnumTable` | `QEnumTable/v1` | 2 | -- | embedded |
| `ActionField` | `ActionField/v1` | 2 | -- | embedded |
| `Action` | `Action/v1` | 2 | `ACTION` | persisted |
| `ConsequentialAction` | `ConsequentialAction/v1` | 3 | `CONSEQUENTIAL_ACTION` | persisted |
| `FieldSpec` | `FieldSpec/v1` | 6 | -- | embedded |
| `ActionKindSpec` | `ActionKindSpec/v1` | 2 | -- | embedded |
| `ActionSchema` | `ActionSchema/v1` | 3 | `ACTION_SCHEMA` | persisted |
| `PredicateSpec` | `PredicateSpec/v1` | 9 | -- | embedded |
| `PredicateSchema` | `PredicateSchema/v1` | 2 | `PREDICATE_SCHEMA` | persisted |
| `FieldTerm` | `FieldTerm/v1` | 2 | -- | embedded |
| `ActionTerm` | `ActionTerm/v1` | 2 | -- | embedded |
| `ProgramRule` | `ProgramRule/v1` | 2 | -- | embedded |
| `DecisionProgram` | `DecisionProgram/v1` | 3 | `POLICY_PROGRAM` | persisted |
| `ImplicationRule` | `ImplicationRule/v1` | 5 | -- | embedded |
| `DefinitionRule` | `DefinitionRule/v1` | 5 | -- | embedded |
| `EntailmentRules` | `EntailmentRules/v1` | 2 | `ENTAILMENT_RULES` | persisted |
| `AdmissibilityDescriptor` | `AdmissibilityDescriptor/v1` | 7 | `ADMISSIBILITY_DESCRIPTOR` | embedded |
| `AdmissibilityDescriptors` | `AdmissibilityDescriptors/v1` | 2 | `ADMISSIBILITY_DESCRIPTORS` | persisted |
| `DisclosureEntry` | `DisclosureEntry/v1` | 7 | `DISCLOSURE_ENTRY` | embedded |
| `DisclosurePolicy` | `DisclosurePolicy/v1` | 2 | `DISCLOSURE_POLICY` | persisted |
| `RatificationRecord` | `RatificationRecord/v1` | 7 | `RATIFICATION_RECORD` | persisted |
| `RatificationSet` | `RatificationSet/v1` | 2 | `RATIFICATION_SET` | persisted |
| `BundleManifest` | `BundleManifest/v1` | 17 | `MANIFEST` | persisted |
| `SignedManifest` | `SignedManifest/v1` | 2 | -- | persisted |
| `ExactValue` | `ExactValue/v1` | 1 | -- | embedded |
| `ClosedLowerBound` | `ClosedLowerBound/v1` | 1 | -- | embedded |
| `ClosedUpperBound` | `ClosedUpperBound/v1` | 1 | -- | embedded |
| `EnumSubset` | `EnumSubset/v1` | 1 | -- | embedded |
| `AcquisitionPayload` | `AcquisitionPayload/v1` | 15 | `ATTESTATION_PAYLOAD` | embedded |
| `VerificationReceipt` | `VerificationReceipt/v1` | 2 | `VERIFICATION_RECEIPT` | persisted |
| `StatementRecord` | `StatementRecord/v1` | 12 | `STATEMENT` | persisted |
| `InterestAssessment` | `InterestAssessment/v1` | 11 | `INTEREST_ASSESSMENT` | persisted |
| `PartyRecord` | `PartyRecord/v1` | 4 | -- | embedded |
| `CaseConstructionRecord` | `CaseConstructionRecord/v1` | 10 | `CASE_CONSTRUCTION` | persisted |
| `Retraction` | `Retraction/v1` | 6 | -- | embedded |
| `Declaration` | `Declaration/v1` | 6 | -- | embedded |
| `TranscriptPrefix` | `TranscriptPrefix/v1` | 3 | `TRANSCRIPT_PREFIX` | derived |
| `ResourceScope` | `ResourceScope/v1` | 2 | -- | embedded |
| `AuthorityGrant` | `AuthorityGrant/v1` | 8 | -- | embedded |
| `AuthorityRegistrySnapshot` | `AuthorityRegistrySnapshot/v1` | 5 | `AUTHORITY_REGISTRY_SNAPSHOT` | persisted |
| `AuthorityRegistrySnapshotBody` | `AuthorityRegistrySnapshotBody/v1` | 2 | `AUTHORITY_REGISTRY_SNAPSHOT_BODY` | embedded |
| `SignedAuthorityRegistrySnapshot` | `SignedAuthorityRegistrySnapshot/v1` | 2 | -- | persisted |
| `RevocationSnapshot` | `RevocationSnapshot/v1` | 4 | `REVOCATION_SNAPSHOT` | persisted |
| `RevocationSnapshotBody` | `RevocationSnapshotBody/v1` | 2 | `REVOCATION_SNAPSHOT_BODY` | embedded |
| `SignedRevocationSnapshot` | `SignedRevocationSnapshot/v1` | 2 | -- | persisted |
| `AgentProfile` | `AgentProfile/v1` | 9 | -- | embedded |
| `AgentCatalogSnapshot` | `AgentCatalogSnapshot/v1` | 5 | `AGENT_CATALOG_SNAPSHOT` | persisted |
| `AgentCatalogSnapshotBody` | `AgentCatalogSnapshotBody/v1` | 2 | `AGENT_CATALOG_SNAPSHOT_BODY` | embedded |
| `SignedAgentCatalogSnapshot` | `SignedAgentCatalogSnapshot/v1` | 2 | -- | persisted |
| `AttestedBy` | `AttestedBy/v1` | 1 | -- | embedded |
| `EntailedBy` | `EntailedBy/v1` | 5 | -- | embedded |
| `EstablishedFact` | `EstablishedFact/v1` | 3 | `ESTABLISHED_FACT` | embedded |
| `StructuralDeriv` | `StructuralDeriv/v1` | 1 | -- | embedded |
| `AdverseDeriv` | `AdverseDeriv/v1` | 4 | -- | embedded |
| `BracketDeriv` | `BracketDeriv/v1` | 4 | -- | embedded |
| `StipulationDeriv` | `StipulationDeriv/v1` | 2 | -- | embedded |
| `AttestedRelationDeriv` | `AttestedRelationDeriv/v1` | 2 | -- | embedded |
| `PolicyEntailmentDeriv` | `PolicyEntailmentDeriv/v1` | 4 | -- | embedded |
| `Constraint` | `Constraint/v1` | 3 | `CONSTRAINT` | embedded |
| `NonEffect` | `NonEffect/v1` | 4 | -- | embedded |
| `AuthorizationContext` | `AuthorizationContext/v1` | 4 | `AUTHORIZATION_CONTEXT` | persisted |
| `RebuildInputs` | `RebuildInputs/v1` | 8 | `REBUILD_INPUTS` | derived |
| `CaseRevision` | `CaseRevision/v1` | 13 | `CASE_REVISION` | persisted |
| `RevisionLineage` | `RevisionLineage/v1` | 8 | `REVISION_LINEAGE` | persisted |
| `Binding` | `Binding/v1` | 2 | -- | embedded |
| `World` | `World/v1` | 1 | `WORLD` | embedded |
| `QueryDecl` | `QueryDecl/v1` | 4 | -- | embedded |
| `LabeledAssertion` | `LabeledAssertion/v1` | 2 | -- | embedded |
| `EnumDeclaration` | `EnumDeclaration/v1` | 2 | -- | embedded |
| `SolverQuery` | `SolverQuery/v1` | 5 | `SOLVER_QUERY` | derived |
| `SolverFingerprint` | `SolverFingerprint/v1` | 5 | -- | embedded |
| `TruncatedReachable` | `TruncatedReachable/v1` | 2 | -- | embedded |
| `DeletionWitness` | `DeletionWitness/v1` | 3 | -- | embedded |
| `ProvenSupport` | `ProvenSupport/v1` | 3 | -- | embedded |
| `UnprovenSupport` | `UnprovenSupport/v1` | 3 | -- | embedded |
| `InvariantOutcome` | `InvariantOutcome/v1` | 3 | -- | embedded |
| `DivergentOutcome` | `DivergentOutcome/v1` | 3 | -- | embedded |
| `InfeasibleOutcome` | `InfeasibleOutcome/v1` | 1 | -- | embedded |
| `IndeterminateOutcome` | `IndeterminateOutcome/v1` | 1 | -- | embedded |
| `LogicalCase` | `LogicalCase/v1` | 6 | `LOGICAL_CASE` | derived |
| `KernelAnalysisRecord` | `KernelAnalysisRecord/v1` | 5 | `KERNEL_ANALYSIS_RECORD` | persisted |
| `EvidenceTarget` | `EvidenceTarget/v1` | 3 | -- | embedded |
| `EvidenceRequest` | `EvidenceRequest/v1` | 4 | `EVIDENCE_REQUEST` | persisted |
| `HumanEscalation` | `HumanEscalation/v1` | 2 | -- | embedded |
| `PlanningRecord` | `PlanningRecord/v1` | 2 | -- | embedded |
| `DiagnosticAnnex` | `DiagnosticAnnex/v1` | 3 | `DIAGNOSTIC_ANNEX` | persisted |
| `AnalysisCertificate` | `AnalysisCertificate/v1` | 8 | `ANALYSIS_CERTIFICATE` | persisted |
| `InternalAnalysisRecord` | `InternalAnalysisRecord/v1` | 4 | `INTERNAL_ANALYSIS_RECORD` | persisted |
| `CommitmentLeaf` | `CommitmentLeaf/v1` | 7 | `MERKLE_LEAF` | derived |
| `CommitmentRoot` | `CommitmentRoot/v1` | 7 | `MERKLE_ROOT` | derived |
| `ProofStep` | `ProofStep/v1` | 2 | -- | embedded |
| `CommitmentEnvelope` | `CommitmentEnvelope/v1` | 10 | `COMMITMENT_ENVELOPE` | persisted |
| `SignedCommitmentEnvelope` | `SignedCommitmentEnvelope/v1` | 2 | -- | persisted |
| `Disclosure` | `Disclosure/v1` | 4 | -- | embedded |
| `ParticipantView` | `ParticipantView/v1` | 6 | `PARTICIPANT_VIEW` | persisted |
| `AuditorView` | `AuditorView/v1` | 5 | `AUDITOR_VIEW` | persisted |
| `RatificationRecordBody` | `RatificationRecordBody/v1` | 6 | `RATIFICATION_RECORD_BODY` | derived |
| `StatementRecordBody` | `StatementRecordBody/v1` | 11 | `STATEMENT_BODY` | derived |
| `InterestAssessmentBody` | `InterestAssessmentBody/v1` | 10 | `INTEREST_ASSESSMENT_BODY` | derived |
| `CaseConstructionRecordBody` | `CaseConstructionRecordBody/v1` | 9 | `CASE_CONSTRUCTION_BODY` | derived |
| `RetractionBody` | `RetractionBody/v1` | 5 | `RETRACTION_BODY` | derived |
| `DeclarationBody` | `DeclarationBody/v1` | 5 | `DECLARATION_BODY` | derived |
| `RevisionLineageBody` | `RevisionLineageBody/v1` | 7 | `REVISION_LINEAGE_BODY` | derived |

## Unions

| Type | Variants |
|---|---|
| `Sort` | `Bool`, `Int`, `Scaled`, `Enum` |
| `Domain` | `BoolDomain`, `IntRange`, `ScaledRange`, `EnumDomain` |
| `Value` | `VBool`, `VInt`, `VScaled`, `VEnum` |
| `Term` | `Var`, `LitBool`, `LitInt`, `LitScaled`, `LitEnum`, `Not`, `Neg`, `And`, `Or`, `Add`, `Implies`, `Iff`, `Sub`, `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`, `MulConst`, `Scale`, `Rescale`, `Ite`, `EnumTable` |
| `QTerm` | `QVar`, `LitBool`, `LitInt`, `LitScaled`, `LitEnum`, `Not`, `Neg`, `And`, `Or`, `Add`, `Implies`, `Iff`, `Sub`, `Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`, `MulConst`, `Scale`, `Rescale`, `Ite`, `EnumTable` |
| `EntailmentRule` | `Implication`, `Definition` |
| `AcquisitionRelation` | `ExactValue`, `ClosedLowerBound`, `ClosedUpperBound`, `EnumSubset` |
| `TranscriptEntry` | `Attestation`, `Statement`, `Retraction`, `Declaration` |
| `Justification` | `AttestedBy`, `EntailedBy` |
| `ConstraintDerivation` | `Structural`, `InterestAdverseBound`, `OpposedBracket`, `PartyStipulation`, `AttestedRelation`, `PolicyEntailment` |
| `ReachableActions` | `Exact`, `Truncated`, `NotComputed` |
| `SupportResult` | `ProvenIrredundantSupport`, `SufficientSupportIrredundanceUnproved` |
| `AnalysisOutcome` | `Invariant`, `Divergent`, `Infeasible`, `Indeterminate` |
| `PlanningOutcome` | `NoActionRequired`, `EvidenceRequested`, `NoSufficientSetAcquirable`, `PlanningIndeterminate` |

## Digest kinds

| Kind | Type |
|---|---|
| `ACTION` | `Action` |
| `ACTION_SCHEMA` | `ActionSchema` |
| `ADMISSIBILITY_DESCRIPTOR` | `AdmissibilityDescriptor` |
| `ADMISSIBILITY_DESCRIPTORS` | `AdmissibilityDescriptors` |
| `AGENT_CATALOG_SNAPSHOT` | `AgentCatalogSnapshot` |
| `AGENT_CATALOG_SNAPSHOT_BODY` | `AgentCatalogSnapshotBody` |
| `ANALYSIS_CERTIFICATE` | `AnalysisCertificate` |
| `ATTESTATION_PAYLOAD` | `AcquisitionPayload` |
| `AUDITOR_VIEW` | `AuditorView` |
| `AUTHORITY_REGISTRY_SNAPSHOT` | `AuthorityRegistrySnapshot` |
| `AUTHORITY_REGISTRY_SNAPSHOT_BODY` | `AuthorityRegistrySnapshotBody` |
| `AUTHORIZATION_CONTEXT` | `AuthorizationContext` |
| `CASE_CONSTRUCTION` | `CaseConstructionRecord` |
| `CASE_CONSTRUCTION_BODY` | `CaseConstructionRecordBody` |
| `CASE_REVISION` | `CaseRevision` |
| `COMMITMENT_ENVELOPE` | `CommitmentEnvelope` |
| `CONSEQUENTIAL_ACTION` | `ConsequentialAction` |
| `CONSTRAINT` | `Constraint` |
| `DECLARATION_BODY` | `DeclarationBody` |
| `DIAGNOSTIC_ANNEX` | `DiagnosticAnnex` |
| `DISCLOSURE_ENTRY` | `DisclosureEntry` |
| `DISCLOSURE_POLICY` | `DisclosurePolicy` |
| `ENTAILMENT_RULES` | `EntailmentRules` |
| `ESTABLISHED_FACT` | `EstablishedFact` |
| `EVIDENCE_REQUEST` | `EvidenceRequest` |
| `INTEREST_ASSESSMENT` | `InterestAssessment` |
| `INTEREST_ASSESSMENT_BODY` | `InterestAssessmentBody` |
| `INTERNAL_ANALYSIS_RECORD` | `InternalAnalysisRecord` |
| `KERNEL_ANALYSIS_RECORD` | `KernelAnalysisRecord` |
| `LOGICAL_CASE` | `LogicalCase` |
| `MANIFEST` | `BundleManifest` |
| `MERKLE_LEAF` | `CommitmentLeaf` |
| `MERKLE_ROOT` | `CommitmentRoot` |
| `PARTICIPANT_VIEW` | `ParticipantView` |
| `POLICY_PROGRAM` | `DecisionProgram` |
| `PREDICATE_SCHEMA` | `PredicateSchema` |
| `QUERY_TERM` | `QTerm` |
| `RATIFICATION_RECORD` | `RatificationRecord` |
| `RATIFICATION_RECORD_BODY` | `RatificationRecordBody` |
| `RATIFICATION_SET` | `RatificationSet` |
| `REBUILD_INPUTS` | `RebuildInputs` |
| `RETRACTION_BODY` | `RetractionBody` |
| `REVISION_LINEAGE` | `RevisionLineage` |
| `REVISION_LINEAGE_BODY` | `RevisionLineageBody` |
| `REVOCATION_SNAPSHOT` | `RevocationSnapshot` |
| `REVOCATION_SNAPSHOT_BODY` | `RevocationSnapshotBody` |
| `SOLVER_QUERY` | `SolverQuery` |
| `STATEMENT` | `StatementRecord` |
| `STATEMENT_BODY` | `StatementRecordBody` |
| `SYMBOL_REF` | `SymbolRef` |
| `TERM` | `Term` |
| `TRANSCRIPT_ENTRY` | `TranscriptEntry` |
| `TRANSCRIPT_PREFIX` | `TranscriptPrefix` |
| `VERIFICATION_RECEIPT` | `VerificationReceipt` |
| `WORLD` | `World` |

## Uniqueness constraints

| Type | Collection | Key |
|---|---|---|
| `Action` | `fields` | `name` |
| `ConsequentialAction` | `consequential_fields` | `name` |
| `ActionKindSpec` | `fields` | `name` |
| `ActionSchema` | `kinds` | `kind` |
| `PredicateSchema` | `predicates` | `predicate_id` |
| `ActionTerm` | `fields` | `name` |
| `EntailmentRules` | `rules` | `rule_id` |
| `AdmissibilityDescriptors` | `descriptors` | `rule_id` |
| `DisclosurePolicy` | `entries` | `outcome_class`, `action_kind`, `audience_class`, `disclosure_context` |
| `RatificationSet` | `records` | `ratification_id` |
| `CaseConstructionRecord` | `parties` | `principal_id` |
| `AuthorityRegistrySnapshot` | `grants` | `key_ref`, `source_class` |
| `AgentCatalogSnapshot` | `profiles` | `agent_id`, `version` |
| `CaseRevision` | `established` | `ref` |
| `CaseRevision` | `constraints` | `label` |
| `CaseRevision` | `non_effects` | `rule_id`, `subject` |
| `World` | `bindings` | `ref` |
| `SolverQuery` | `enums` | `enum_id` |
| `SolverQuery` | `declarations` | `side`, `ref` |
| `SolverQuery` | `assertions` | `label` |
| `EvidenceRequest` | `targets` | `proposition` |
| `ParticipantView` | `disclosures` | `path` |
| `AuditorView` | `disclosures` | `path` |
| `CaseConstructionRecordBody` | `parties` | `principal_id` |

## Full grammar

```
Instant                      = INT
Signature                    = REC("Signature/v1", 2, [ATOM alg, BYTES sig])
HalfOpenInterval             = REC("HalfOpen/v1", 2, [Instant start, Option[Instant] end])
SymbolRef                    = REC("SymbolRef/v1", 2, [ATOM predicate_id, SEQ[ATOM] args])
SymbolRefTemplate            = REC("SymbolRefTemplate/v1", 2, [ATOM predicate_id, SEQ[ATOM] args_or_binders])
ScaledSort                   = REC("ScaledSort/v1", 2, [ATOM unit_tag, INT scale])
EnumSort                     = REC("EnumSort/v1", 1, [ATOM enum_id])
Sort                         = TAGGED("Bool", UNIT)
                             | TAGGED("Int", UNIT)
                             | TAGGED("Scaled", ScaledSort)
                             | TAGGED("Enum", EnumSort)
IntRange                     = REC("IntRange/v1", 2, [INT lo, INT hi])
ScaledRange                  = REC("ScaledRange/v1", 2, [INT lo, INT hi])
EnumDomain                   = REC("EnumDomain/v1", 1, [SEQ[ATOM]^>=1 members])
Domain                       = TAGGED("BoolDomain", UNIT)
                             | TAGGED("IntRange", IntRange)
                             | TAGGED("ScaledRange", ScaledRange)
                             | TAGGED("EnumDomain", EnumDomain)
VScaled                      = REC("VScaled/v1", 3, [ATOM unit_tag, INT scale, INT minor])
VEnum                        = REC("VEnum/v1", 2, [ATOM enum_id, ATOM member])
Value                        = TAGGED("VBool", BOOL)
                             | TAGGED("VInt", INT)
                             | TAGGED("VScaled", VScaled)
                             | TAGGED("VEnum", VEnum)
QueryVar                     = REC("QueryVar/v1", 2, [ATOM<S|L|R> side, SymbolRef ref])
Bin                          = REC("Bin/v1", 2, [Term left, Term right])
MulConst                     = REC("MulConst/v1", 2, [INT k, Term a])
Scale                        = REC("Scale/v1", 3, [Term a, INT k, Sort to])
Rescale                      = REC("Rescale/v1", 2, [Term a, INT to_scale])
Ite                          = REC("Ite/v1", 3, [Term cond, Term if_true, Term if_false])
Arm                          = REC("Arm/v1", 2, [ATOM member, Term term])
EnumTable                    = REC("EnumTable/v1", 2, [Term scrutinee, SEQ[Arm]^>=1 arms])
Term                         = TAGGED("Var", SymbolRef)
                             | TAGGED("LitBool", BOOL)
                             | TAGGED("LitInt", INT)
                             | TAGGED("LitScaled", VScaled)
                             | TAGGED("LitEnum", VEnum)
                             | TAGGED("Not", Term)
                             | TAGGED("Neg", Term)
                             | TAGGED("And", SEQ[Term]^>=2)
                             | TAGGED("Or", SEQ[Term]^>=2)
                             | TAGGED("Add", SEQ[Term]^>=2)
                             | TAGGED("Implies", Bin)
                             | TAGGED("Iff", Bin)
                             | TAGGED("Sub", Bin)
                             | TAGGED("Eq", Bin)
                             | TAGGED("Ne", Bin)
                             | TAGGED("Lt", Bin)
                             | TAGGED("Le", Bin)
                             | TAGGED("Gt", Bin)
                             | TAGGED("Ge", Bin)
                             | TAGGED("MulConst", MulConst)
                             | TAGGED("Scale", Scale)
                             | TAGGED("Rescale", Rescale)
                             | TAGGED("Ite", Ite)
                             | TAGGED("EnumTable", EnumTable)
QBin                         = REC("QBin/v1", 2, [QTerm left, QTerm right])
QMulConst                    = REC("QMulConst/v1", 2, [INT k, QTerm a])
QScale                       = REC("QScale/v1", 3, [QTerm a, INT k, Sort to])
QRescale                     = REC("QRescale/v1", 2, [QTerm a, INT to_scale])
QIte                         = REC("QIte/v1", 3, [QTerm cond, QTerm if_true, QTerm if_false])
QArm                         = REC("QArm/v1", 2, [ATOM member, QTerm term])
QEnumTable                   = REC("QEnumTable/v1", 2, [QTerm scrutinee, SEQ[QArm]^>=1 arms])
QTerm                        = TAGGED("QVar", QueryVar)
                             | TAGGED("LitBool", BOOL)
                             | TAGGED("LitInt", INT)
                             | TAGGED("LitScaled", VScaled)
                             | TAGGED("LitEnum", VEnum)
                             | TAGGED("Not", QTerm)
                             | TAGGED("Neg", QTerm)
                             | TAGGED("And", SEQ[QTerm]^>=2)
                             | TAGGED("Or", SEQ[QTerm]^>=2)
                             | TAGGED("Add", SEQ[QTerm]^>=2)
                             | TAGGED("Implies", QBin)
                             | TAGGED("Iff", QBin)
                             | TAGGED("Sub", QBin)
                             | TAGGED("Eq", QBin)
                             | TAGGED("Ne", QBin)
                             | TAGGED("Lt", QBin)
                             | TAGGED("Le", QBin)
                             | TAGGED("Gt", QBin)
                             | TAGGED("Ge", QBin)
                             | TAGGED("MulConst", QMulConst)
                             | TAGGED("Scale", QScale)
                             | TAGGED("Rescale", QRescale)
                             | TAGGED("Ite", QIte)
                             | TAGGED("EnumTable", QEnumTable)
ActionField                  = REC("ActionField/v1", 2, [ATOM name, Value value])
Action                       = REC("Action/v1", 2, [ATOM kind, SEQ[ActionField] fields])
ConsequentialAction          = REC("ConsequentialAction/v1", 3, [DIGEST action_schema_digest, ATOM kind, SEQ[ActionField] consequential_fields])
FieldSpec                    = REC("FieldSpec/v1", 6, [ATOM name, Sort sort, Domain bounds, ATOM<CONSEQUENTIAL|DIAGNOSTIC> consequentiality, BOOL required, Option[Value] default])
ActionKindSpec               = REC("ActionKindSpec/v1", 2, [ATOM kind, SEQ[FieldSpec] fields])
ActionSchema                 = REC("ActionSchema/v1", 3, [ATOM schema_id, INT schema_version, SEQ[ActionKindSpec]^>=1 kinds])
PredicateSpec                = REC("PredicateSpec/v1", 9, [ATOM predicate_id, SEQ[ATOM] arg_kinds, Sort value_sort, Domain domain, ATOM<OBSERVATION|RECORD|NORMATIVE> layer, ATOM<ATTESTABLE|DERIVED> acquisition, SET[ATOM] permitted_source_classes, SET[ATOM] resource_scope_kinds, Option[ATOM] measurement_class])
PredicateSchema              = REC("PredicateSchema/v1", 2, [INT schema_version, SEQ[PredicateSpec] predicates])
FieldTerm                    = REC("FieldTerm/v1", 2, [ATOM name, Term term])
ActionTerm                   = REC("ActionTerm/v1", 2, [ATOM kind, SEQ[FieldTerm] fields])
ProgramRule                  = REC("ProgramRule/v1", 2, [Term guard, ActionTerm action])
DecisionProgram              = REC("DecisionProgram/v1", 3, [SEQ[SymbolRef] inputs, SEQ[ProgramRule] rules, ActionTerm otherwise])
ImplicationRule              = REC("ImplicationRule/v1", 5, [ATOM rule_id, SEQ[ATOM] binder_args, SymbolRefTemplate conclusion, Term premise, Term conclusion_value])
DefinitionRule               = REC("DefinitionRule/v1", 5, [ATOM rule_id, SEQ[ATOM] binder_args, SymbolRefTemplate conclusion, Term premise, DIGEST exhaustiveness_ratification_ref])
EntailmentRule               = TAGGED("Implication", ImplicationRule)
                             | TAGGED("Definition", DefinitionRule)
EntailmentRules              = REC("EntailmentRules/v1", 2, [INT schema_version, SEQ[EntailmentRule] rules])
AdmissibilityDescriptor      = REC("AdmissibilityDescriptor/v1", 7, [ATOM rule_id, INT rule_version, ATOM rule_kind, ATOM grouping_key, SET[ATOM] admissible_procedures, INT max_temporal_gap, Option[DIGEST] ratification_ref])
AdmissibilityDescriptors     = REC("AdmissibilityDescriptors/v1", 2, [INT schema_version, SEQ[AdmissibilityDescriptor] descriptors])
DisclosureEntry              = REC("DisclosureEntry/v1", 7, [ATOM<INVARIANT|DIVERGENT|INFEASIBLE|INDETERMINATE> outcome_class, Option[ATOM] action_kind, ATOM audience_class, ATOM disclosure_context, BOOL reveals_sensitive_input, Option[DIGEST] inference_acknowledgement_ref, SEQ[ATOM] permitted_paths])
DisclosurePolicy             = REC("DisclosurePolicy/v1", 2, [INT schema_version, SEQ[DisclosureEntry] entries])
RatificationRecord           = REC("RatificationRecord/v1", 7, [ATOM ratification_id, Option[ATOM] tenant_scope, ATOM subject_kind, DIGEST subject_ref, Instant ratified_at, ATOM signer_key_ref, Signature signature])
RatificationSet              = REC("RatificationSet/v1", 2, [INT schema_version, SEQ[RatificationRecord] records])
BundleManifest               = REC("BundleManifest/v1", 17, [INT manifest_schema_version, Option[ATOM] tenant_scope, ATOM policy_id, ATOM human_version, HalfOpenInterval effective_interval, DIGEST decision_program_digest, DIGEST entailment_rules_digest, DIGEST admissibility_descriptors_digest, DIGEST predicate_schema_digest, DIGEST action_schema_digest, DIGEST disclosure_policy_digest, DIGEST ratification_records_digest, INT ir_schema_version, INT interpreter_version, ATOM ratified_by, Instant ratified_at, ATOM signer_key_ref])
SignedManifest               = REC("SignedManifest/v1", 2, [BundleManifest manifest, Signature signature])
ExactValue                   = REC("ExactValue/v1", 1, [Value value])
ClosedLowerBound             = REC("ClosedLowerBound/v1", 1, [Value bound])
ClosedUpperBound             = REC("ClosedUpperBound/v1", 1, [Value bound])
EnumSubset                   = REC("EnumSubset/v1", 1, [SET[Value]^>=1 allowed])
AcquisitionRelation          = TAGGED("ExactValue", ExactValue)
                             | TAGGED("ClosedLowerBound", ClosedLowerBound)
                             | TAGGED("ClosedUpperBound", ClosedUpperBound)
                             | TAGGED("EnumSubset", EnumSubset)
AcquisitionPayload           = REC("AcquisitionPayload/v1", 15, [ATOM tenant_id, ATOM case_id, ATOM subject, SymbolRef proposition, AcquisitionRelation relation, Sort value_sort, DIGEST predicate_schema_digest, Instant observed_at, Instant issued_at, HalfOpenInterval validity, BYTES[16] nonce, ATOM source_class, ATOM signer_key_ref, INT authorization_policy_version, DIGEST request_id])
VerificationReceipt          = REC("VerificationReceipt/v1", 2, [AcquisitionPayload payload, Signature signature])
StatementRecord              = REC("StatementRecord/v1", 12, [ATOM tenant_id, ATOM case_id, ATOM claimant, ATOM role_in_case, SymbolRef proposition, Value asserted_value, Sort value_sort, Option[ATOM] measurement_procedure_id, Instant statement_time, Option[DIGEST] supersedes, ATOM signer_key_ref, Signature signature])
InterestAssessment           = REC("InterestAssessment/v1", 11, [ATOM tenant_id, ATOM case_id, SymbolRef proposition, ATOM principal_id, ATOM scope, ATOM direction, HalfOpenInterval validity, ATOM issuer, Option[DIGEST] supersedes, ATOM signer_key_ref, Signature signature])
PartyRecord                  = REC("PartyRecord/v1", 4, [ATOM tenant_id, ATOM principal_id, ATOM role_in_case, SET[ATOM] competences])
CaseConstructionRecord       = REC("CaseConstructionRecord/v1", 10, [ATOM tenant_id, ATOM case_id, Instant created_at, SEQ[ATOM] subject_refs, Option[ATOM] contract_ref, SEQ[PartyRecord] parties, SEQ[SymbolRef] declared_instances, SET[ResourceScope] case_scope_coordinates, ATOM signer_key_ref, Signature signature])
Retraction                   = REC("Retraction/v1", 6, [ATOM tenant_id, ATOM case_id, DIGEST target, Instant at, ATOM signer_key_ref, Signature signature])
Declaration                  = REC("Declaration/v1", 6, [ATOM tenant_id, ATOM case_id, SEQ[SymbolRef]^>=1 instances, Instant at, ATOM signer_key_ref, Signature signature])
TranscriptPrefix             = REC("TranscriptPrefix/v1", 3, [ATOM tenant_id, ATOM case_id, SEQ[DIGEST] entry_digests])
TranscriptEntry              = TAGGED("Attestation", VerificationReceipt)
                             | TAGGED("Statement", StatementRecord)
                             | TAGGED("Retraction", Retraction)
                             | TAGGED("Declaration", Declaration)
ResourceScope                = REC("ResourceScope/v1", 2, [ATOM scope_kind, ATOM scope_value])
AuthorityGrant               = REC("AuthorityGrant/v1", 8, [ATOM key_ref, ATOM principal_id, ATOM tenant_scope, ATOM source_class, SET[ATOM]^>=1 permitted_predicates, SET[ResourceScope]^>=1 resource_scope, HalfOpenInterval validity, INT authorization_policy_version])
AuthorityRegistrySnapshot    = REC("AuthorityRegistrySnapshot/v1", 5, [ATOM registry_id, ATOM tenant_id, INT authorization_policy_version, SEQ[AuthorityGrant] grants, Instant published_at])
AuthorityRegistrySnapshotBody = REC("AuthorityRegistrySnapshotBody/v1", 2, [AuthorityRegistrySnapshot snapshot, ATOM signer_key_ref])
SignedAuthorityRegistrySnapshot = REC("SignedAuthorityRegistrySnapshot/v1", 2, [AuthorityRegistrySnapshotBody body, Signature signature])
RevocationSnapshot           = REC("RevocationSnapshot/v1", 4, [ATOM registry_id, ATOM tenant_id, SET[ATOM] revoked_key_refs, Instant published_at])
RevocationSnapshotBody       = REC("RevocationSnapshotBody/v1", 2, [RevocationSnapshot snapshot, ATOM signer_key_ref])
SignedRevocationSnapshot     = REC("SignedRevocationSnapshot/v1", 2, [RevocationSnapshotBody body, Signature signature])
AgentProfile                 = REC("AgentProfile/v1", 9, [ATOM agent_id, INT version, ATOM tenant_id, ATOM principal_id, ATOM source_class, SET[ATOM]^>=1 acquirable_predicates, SET[ResourceScope]^>=1 resource_scope, ATOM endpoint_ref, ATOM<ACTIVE|RETIRED> lifecycle])
AgentCatalogSnapshot         = REC("AgentCatalogSnapshot/v1", 5, [ATOM catalog_id, ATOM tenant_id, SEQ[AgentProfile] profiles, Instant published_at, DIGEST authority_registry_snapshot_digest])
AgentCatalogSnapshotBody     = REC("AgentCatalogSnapshotBody/v1", 2, [AgentCatalogSnapshot snapshot, ATOM signer_key_ref])
SignedAgentCatalogSnapshot   = REC("SignedAgentCatalogSnapshot/v1", 2, [AgentCatalogSnapshotBody body, Signature signature])
AttestedBy                   = REC("AttestedBy/v1", 1, [DIGEST receipt_digest])
EntailedBy                   = REC("EntailedBy/v1", 5, [DIGEST manifest_digest, ATOM<IMPLICATION|DEFINITION> modality, ATOM<RULE_FIRED|FULL_EVALUATION|WITNESS_DISJUNCT> derivation_mode, SEQ[ATOM]^>=1 rule_ids, SEQ[DIGEST] premise_digests])
Justification                = TAGGED("AttestedBy", AttestedBy)
                             | TAGGED("EntailedBy", EntailedBy)
EstablishedFact              = REC("EstablishedFact/v1", 3, [SymbolRef ref, Value value, Justification justification])
StructuralDeriv              = REC("StructuralDeriv/v1", 1, [DIGEST predicate_schema_digest])
AdverseDeriv                 = REC("AdverseDeriv/v1", 4, [INT rule_version, SEQ[DIGEST] sources, SEQ[DIGEST] dependencies, DIGEST descriptor_digest])
BracketDeriv                 = REC("BracketDeriv/v1", 4, [INT rule_version, SEQ[DIGEST] sources, SEQ[DIGEST] dependencies, DIGEST descriptor_digest])
StipulationDeriv             = REC("StipulationDeriv/v1", 2, [INT rule_version, SEQ[DIGEST]^>=1 statement_digests])
AttestedRelationDeriv        = REC("AttestedRelationDeriv/v1", 2, [INT rule_version, DIGEST receipt_digest])
PolicyEntailmentDeriv        = REC("PolicyEntailmentDeriv/v1", 4, [DIGEST manifest_digest, ATOM<IMPLICATION|DEFINITION> modality, SEQ[ATOM]^>=1 rule_ids, Option[DIGEST] ratification_ref])
ConstraintDerivation         = TAGGED("Structural", StructuralDeriv)
                             | TAGGED("InterestAdverseBound", AdverseDeriv)
                             | TAGGED("OpposedBracket", BracketDeriv)
                             | TAGGED("PartyStipulation", StipulationDeriv)
                             | TAGGED("AttestedRelation", AttestedRelationDeriv)
                             | TAGGED("PolicyEntailment", PolicyEntailmentDeriv)
Constraint                   = REC("Constraint/v1", 3, [ATOM[<=100] label, Term formula, ConstraintDerivation derivation])
NonEffect                    = REC("NonEffect/v1", 4, [ATOM rule_id, INT rule_version, ATOM subject, ATOM reason])
AuthorizationContext         = REC("AuthorizationContext/v1", 4, [INT authorization_policy_version, DIGEST authority_registry_snapshot_digest, DIGEST revocation_snapshot_digest, HalfOpenInterval context_validity])
RebuildInputs                = REC("RebuildInputs/v1", 8, [ATOM tenant_id, ATOM case_id, DIGEST construction_digest, DIGEST transcript_prefix_digest, DIGEST bundle_manifest_digest, Instant as_of, ATOM<OPERATIONAL|COUNTERFACTUAL> mode, DIGEST authorization_context_digest])
CaseRevision                 = REC("CaseRevision/v1", 13, [ATOM tenant_id, ATOM case_id, DIGEST construction_digest, DIGEST transcript_prefix_digest, DIGEST bundle_pin, Instant as_of, ATOM<OPERATIONAL|COUNTERFACTUAL> mode, DIGEST authorization_context_digest, ATOM<AUTHORIZABLE|NEVER_AUTHORIZABLE> authorizability, SEQ[SymbolRef] declared, SEQ[EstablishedFact] established, SEQ[Constraint] constraints, SEQ[NonEffect] non_effects])
RevisionLineage              = REC("RevisionLineage/v1", 8, [ATOM tenant_id, ATOM case_id, DIGEST revision_semantic_digest, INT revision_number, Option[DIGEST] parent_digest, Instant published_at, ATOM signer_key_ref, Signature signature])
Binding                      = REC("Binding/v1", 2, [SymbolRef ref, Value value])
World                        = REC("World/v1", 1, [SEQ[Binding] bindings])
QueryDecl                    = REC("QueryDecl/v1", 4, [ATOM<S|L|R> side, SymbolRef ref, Sort sort, Domain domain])
LabeledAssertion             = REC("LabeledAssertion/v1", 2, [ATOM[<=120] label, QTerm formula])
EnumDeclaration              = REC("EnumDeclaration/v1", 2, [ATOM enum_id, SEQ[ATOM]^>=1 members])
SolverQuery                  = REC("SolverQuery/v1", 5, [ATOM<FEASIBILITY|INVARIANCE|SUFFICIENCY> kind, DIGEST logical_case_digest, SEQ[EnumDeclaration] enums, SEQ[QueryDecl] declarations, SEQ[LabeledAssertion] assertions])
SolverFingerprint            = REC("SolverFingerprint/v1", 5, [ATOM backend, ATOM version, INT seed, ATOM logic, INT budget])
TruncatedReachable           = REC("TruncatedReachable/v1", 2, [SET[ConsequentialAction] sample, INT cap])
ReachableActions             = TAGGED("Exact", SET[ConsequentialAction])
                             | TAGGED("Truncated", TruncatedReachable)
                             | TAGGED("NotComputed", ATOM)
DeletionWitness              = REC("DeletionWitness/v1", 3, [SymbolRef member, World left, World right])
ProvenSupport                = REC("ProvenSupport/v1", 3, [SEQ[SymbolRef] members, DIGEST sufficiency_handle, SEQ[DeletionWitness] deletion_witnesses])
UnprovenSupport              = REC("UnprovenSupport/v1", 3, [SEQ[SymbolRef] members, SEQ[SymbolRef] inconclusive, SEQ[ATOM] reasons])
SupportResult                = TAGGED("ProvenIrredundantSupport", ProvenSupport)
                             | TAGGED("SufficientSupportIrredundanceUnproved", UnprovenSupport)
InvariantOutcome             = REC("InvariantOutcome/v1", 3, [ConsequentialAction action, World witness, DIGEST invariance_query_digest])
DivergentOutcome             = REC("DivergentOutcome/v1", 3, [ReachableActions reachable, World left, World right])
InfeasibleOutcome            = REC("InfeasibleOutcome/v1", 1, [SEQ[ATOM] contributing])
IndeterminateOutcome         = REC("IndeterminateOutcome/v1", 1, [ATOM reason])
AnalysisOutcome              = TAGGED("Invariant", InvariantOutcome)
                             | TAGGED("Divergent", DivergentOutcome)
                             | TAGGED("Infeasible", InfeasibleOutcome)
                             | TAGGED("Indeterminate", IndeterminateOutcome)
LogicalCase                  = REC("LogicalCase/v1", 6, [SEQ[SymbolRef] universe, SEQ[EstablishedFact] known, SEQ[Constraint] constraints, DIGEST decision_program_digest, DIGEST action_schema_digest, DIGEST predicate_schema_digest])
KernelAnalysisRecord         = REC("KernelAnalysisRecord/v1", 5, [DIGEST logical_case_digest, AnalysisOutcome outcome, SEQ[DIGEST] query_digests, SolverFingerprint fingerprint, ATOM determinism_class])
EvidenceTarget               = REC("EvidenceTarget/v1", 3, [SymbolRef proposition, ATOM<ATTESTABLE|DERIVED> acquisition_class, SET[ATOM]^>=1 permitted_source_classes])
EvidenceRequest              = REC("EvidenceRequest/v1", 4, [ATOM tenant_id, ATOM case_id, DIGEST revision_semantic_digest, SEQ[EvidenceTarget]^>=1 targets])
HumanEscalation              = REC("HumanEscalation/v1", 2, [ATOM reason, SEQ[SymbolRef]^>=1 unacquirable])
PlanningOutcome              = TAGGED("NoActionRequired", UNIT)
                             | TAGGED("EvidenceRequested", EvidenceRequest)
                             | TAGGED("NoSufficientSetAcquirable", HumanEscalation)
                             | TAGGED("PlanningIndeterminate", ATOM)
PlanningRecord               = REC("PlanningRecord/v1", 2, [PlanningOutcome planning_outcome, Option[SupportResult] support])
DiagnosticAnnex              = REC("DiagnosticAnnex/v1", 3, [SEQ[ATOM] notes, SEQ[DIGEST] query_digests, Option[ATOM] solver_log_ref])
AnalysisCertificate          = REC("AnalysisCertificate/v1", 8, [INT certificate_schema_version, ATOM tenant_id, ATOM case_id, DIGEST revision_semantic_digest, DIGEST bundle_manifest_digest, KernelAnalysisRecord kernel, PlanningRecord planning, Option[DIGEST] diagnostic_annex_digest])
InternalAnalysisRecord       = REC("InternalAnalysisRecord/v1", 4, [AnalysisCertificate certificate, CaseRevision revision, Option[Action] full_action, BYTES[32] salt_case])
CommitmentLeaf               = REC("CommitmentLeaf/v1", 7, [ATOM tenant_id, DIGEST case_commitment, DIGEST revision_commitment, INT certificate_schema_version, ATOM path, BYTES[32] salt, BYTES value_bytes])
CommitmentRoot               = REC("CommitmentRoot/v1", 7, [ATOM tenant_id, ATOM case_id, DIGEST revision_commitment, DIGEST bundle_manifest_digest, INT certificate_schema_version, INT leaf_count, BYTES[32] merkle])
ProofStep                    = REC("ProofStep/v1", 2, [ATOM<L|R> side, BYTES[32] sibling])
CommitmentEnvelope           = REC("CommitmentEnvelope/v1", 10, [ATOM tenant_id, ATOM case_id, DIGEST case_commitment, DIGEST revision_commitment, DIGEST bundle_manifest_digest, DIGEST disclosure_policy_digest, INT certificate_schema_version, INT leaf_count, BYTES[32] root, ATOM signer_key_ref])
SignedCommitmentEnvelope     = REC("SignedCommitmentEnvelope/v1", 2, [CommitmentEnvelope envelope, Signature signature])
Disclosure                   = REC("Disclosure/v1", 4, [ATOM path, BYTES value_bytes, BYTES[32] salt, SEQ[ProofStep] proof])
ParticipantView              = REC("ParticipantView/v1", 6, [SignedCommitmentEnvelope envelope, ATOM audience_class, ATOM disclosure_context, DIGEST disclosure_entry_digest, SEQ[Disclosure] disclosures, Option[ATOM] inference_notice])
AuditorView                  = REC("AuditorView/v1", 5, [SignedCommitmentEnvelope envelope, ATOM audience_class, ATOM disclosure_context, DIGEST disclosure_entry_digest, SEQ[Disclosure] disclosures])
RatificationRecordBody       = REC("RatificationRecordBody/v1", 6, [ATOM ratification_id, Option[ATOM] tenant_scope, ATOM subject_kind, DIGEST subject_ref, Instant ratified_at, ATOM signer_key_ref])
StatementRecordBody          = REC("StatementRecordBody/v1", 11, [ATOM tenant_id, ATOM case_id, ATOM claimant, ATOM role_in_case, SymbolRef proposition, Value asserted_value, Sort value_sort, Option[ATOM] measurement_procedure_id, Instant statement_time, Option[DIGEST] supersedes, ATOM signer_key_ref])
InterestAssessmentBody       = REC("InterestAssessmentBody/v1", 10, [ATOM tenant_id, ATOM case_id, SymbolRef proposition, ATOM principal_id, ATOM scope, ATOM direction, HalfOpenInterval validity, ATOM issuer, Option[DIGEST] supersedes, ATOM signer_key_ref])
CaseConstructionRecordBody   = REC("CaseConstructionRecordBody/v1", 9, [ATOM tenant_id, ATOM case_id, Instant created_at, SEQ[ATOM] subject_refs, Option[ATOM] contract_ref, SEQ[PartyRecord] parties, SEQ[SymbolRef] declared_instances, SET[ResourceScope] case_scope_coordinates, ATOM signer_key_ref])
RetractionBody               = REC("RetractionBody/v1", 5, [ATOM tenant_id, ATOM case_id, DIGEST target, Instant at, ATOM signer_key_ref])
DeclarationBody              = REC("DeclarationBody/v1", 5, [ATOM tenant_id, ATOM case_id, SEQ[SymbolRef]^>=1 instances, Instant at, ATOM signer_key_ref])
RevisionLineageBody          = REC("RevisionLineageBody/v1", 7, [ATOM tenant_id, ATOM case_id, DIGEST revision_semantic_digest, INT revision_number, Option[DIGEST] parent_digest, Instant published_at, ATOM signer_key_ref])
```
