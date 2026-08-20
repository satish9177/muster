# MUSTER Phase 0.8 -- signing-body report

NON-PRODUCTION SPECIFICATION MATERIAL.  Generated from the registry.

Every signature covers a first-class, named type.  Where the signature
covers 'the record itself', the preimage is a GENERATED body type with its
own tag and digest kind -- not an informal 'record minus signature'.

| Artifact | Signed preimage | Digest domain | Authoritative signer identity |
|---|---|---|---|
| `RatificationRecord` | `RatificationRecordBody` | `RATIFICATION_RECORD_BODY` | `signer_key_ref` |
| `SignedManifest` | `SignedManifest.manifest` | `MANIFEST` | `manifest.signer_key_ref` |
| `VerificationReceipt` | `VerificationReceipt.payload` | `ATTESTATION_PAYLOAD` | `payload.signer_key_ref` |
| `StatementRecord` | `StatementRecordBody` | `STATEMENT_BODY` | `signer_key_ref` |
| `InterestAssessment` | `InterestAssessmentBody` | `INTEREST_ASSESSMENT_BODY` | `signer_key_ref` |
| `CaseConstructionRecord` | `CaseConstructionRecordBody` | `CASE_CONSTRUCTION_BODY` | `signer_key_ref` |
| `Retraction` | `RetractionBody` | `RETRACTION_BODY` | `signer_key_ref` |
| `Declaration` | `DeclarationBody` | `DECLARATION_BODY` | `signer_key_ref` |
| `SignedAuthorityRegistrySnapshot` | `SignedAuthorityRegistrySnapshot.body` | `AUTHORITY_REGISTRY_SNAPSHOT_BODY` | `body.signer_key_ref` |
| `SignedRevocationSnapshot` | `SignedRevocationSnapshot.body` | `REVOCATION_SNAPSHOT_BODY` | `body.signer_key_ref` |
| `SignedAgentCatalogSnapshot` | `SignedAgentCatalogSnapshot.body` | `AGENT_CATALOG_SNAPSHOT_BODY` | `body.signer_key_ref` |
| `RevisionLineage` | `RevisionLineageBody` | `REVISION_LINEAGE_BODY` | `signer_key_ref` |
| `SignedCommitmentEnvelope` | `SignedCommitmentEnvelope.envelope` | `COMMITMENT_ENVELOPE` | `envelope.signer_key_ref` |

`Signature` itself carries only `(alg, sig)`.  It holds no signer reference,
so the payload and the wrapper have nothing to disagree about.

No security-critical field sits outside a signed body.  The Phase 0.7
`VerificationReceipt.revocation_snapshot` -- swappable without resigning --
is gone; revocation is pinned once per rebuild in `AuthorizationContext`,
which is itself inside the semantic `CaseRevision`.
