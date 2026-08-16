# MUSTER Phase 0.8 -- commitment and Merkle report

NON-PRODUCTION SPECIFICATION MATERIAL.

## Frozen path inventory (certificate_schema_version = 1)

| Path | Declared type | Present when |
|---|---|---|
| `case.tenant_id` | `ATOM` | always |
| `case.case_id` | `ATOM` | always |
| `certificate.schema_version` | `INT` | always |
| `bundle.manifest_digest` | `DIGEST` | always |
| `revision.construction_digest` | `DIGEST` | always |
| `revision.transcript_prefix_digest` | `DIGEST` | always |
| `revision.bundle_pin` | `DIGEST` | always |
| `revision.as_of` | `Instant` | always |
| `revision.mode` | `ATOM` | always |
| `revision.authorization_context_digest` | `DIGEST` | always |
| `revision.authorizability` | `ATOM` | always |
| `revision.declared` | `SEQ[SymbolRef]` | always |
| `revision.established.<64 hex>` | `EstablishedFact` | always |
| `revision.constraints.<64 hex>` | `Constraint` | always |
| `revision.non_effects.<64 hex>` | `NonEffect` | always |
| `kernel.logical_case_digest` | `DIGEST` | always |
| `kernel.determinism_class` | `ATOM` | always |
| `kernel.fingerprint` | `SolverFingerprint` | always |
| `kernel.outcome.tag` | `ATOM` | always |
| `kernel.outcome.action` | `ConsequentialAction` | INVARIANT |
| `kernel.outcome.witness` | `World` | INVARIANT |
| `kernel.outcome.reachable` | `ReachableActions` | DIVERGENT |
| `kernel.outcome.left` | `World` | DIVERGENT |
| `kernel.outcome.right` | `World` | DIVERGENT |
| `kernel.outcome.contributing` | `SEQ[ATOM]` | INFEASIBLE |
| `kernel.outcome.reason` | `ATOM` | INDETERMINATE |
| `action.full` | `Action` | INVARIANT |
| `planning.outcome` | `PlanningOutcome` | always |
| `planning.support` | `Option[SupportResult]` | always |

The extractor is total: its output **is** the leaf set.  A tree whose paths
differ from the extractor output is `IncompleteCommitmentSet`.  A path outside
the inventory is `UnknownCommitmentPath`.  Dynamic segments are 64 hex
characters of a domain-separated digest, so they are injective, charset-safe,
fixed width, and do not leak the identifier of an undisclosed item.

## The worked scenario

- committed leaves: **24**
- merkle: `16128d905bc53362f4abd60ac4e741693b8c93aea7373b7d242ecc90869b76ec`
- root: `02743aff28ced52f399f77ccffab4fd204d378f555c102c9ff4f4c25f4cef8d4`
- case commitment (salted): `c5e3625611f970831a8faac71962d8d8cf2e049035a866cfd9730b7cb1a54e8b`
- revision commitment (salted): `3c3d685d2609d830220af529860b2acd9d83060b23d37a711068ba6c4d7a543b`
- revision semantic digest (private): `19b4360987bf1f377dfd976b37a13ae879e4f03ad0e34937c3d791ffba91c2ed`

The last two differ, and only the salted form appears in the envelope.  That
is [B11]: a raw semantic digest is a deterministic function of inputs a
participant may be able to enumerate, so publishing it turns the envelope
into an oracle for private inputs.

## Shapes

```
merkle(0) = SHA-256("muster/v1/MERKLE_EMPTY" || 0x00)
merkle(1) = L0                              -- not hashed again
merkle(2) = node(L0, L1)
merkle(3) = node(node(L0, L1), L2)          -- PROMOTION, never duplication
merkle(4) = node(node(L0, L1), node(L2, L3))
```

Proofs verify at every size 1..8; a promoted node contributes no step.
`leaf_count` is committed in `CommitmentRoot`, and tenant, case commitment,
revision commitment and schema version are bound into **every leaf**, so
transplantation fails at the leaf, not merely at the root.
