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
- merkle: `0eb4618fd28b6607b5c6aa589226cd32f096fb5b223e7c286e037d35eb378ca3`
- root: `96c2a1a1649c78cb2bf2ea91f98d5b794950b7a213daba5abdc905cc62f82aae`
- case commitment (salted): `414806a88e2e8a475354728c5d824d65b21f7373d4cc141de2edb4234f0079fd`
- revision commitment (salted): `3cb40590b8e35aabb8ae70a6fd07150ffc181637e5c5e1601b624fc18621b5b5`
- revision semantic digest (private): `aa610c6c315c51e6f992ad46ea65066c797c1da6e1f9780869b80e975af1f69d`

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
