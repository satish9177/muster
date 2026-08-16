# MUSTER Phase 0.8 — executable wire specification

**THIS IS NOT PRODUCTION CODE. THIS IS NOT `src/muster`. NOTHING HERE IS PHASE 1
IMPLEMENTATION.**

This directory is a *normative design artifact*. It exists to mechanically
validate the frozen Phase-1 contract and to generate the golden vectors that
Phase 1 will be tested against. It is deliberately outside any production source
layout.

## Why it exists

One defect family — canonical encoding, commitments, disclosure envelopes,
disclosure-policy pinning, the `Action`/`ConsequentialAction` split and signing
preimages — survived two full rounds of hand-written prose correction. Both
rounds produced grammars whose productions were right and whose *preimages,
uniqueness rules, arities and coverage* were incomplete. In Phase 0.7 four ATOM
length octets were transcribed wrongly by hand.

Arity, preimage coverage, path totality and uniqueness are not properties prose
review reliably catches. They are properties a checker catches every time. So the
wire surface is specified by a machine-checked artifact instead of by another
list of hex strings.

## The reference/production rule

**The Phase-0.8 reference codec and schema tooling is NOT the production
implementation.**

When production M1 begins:

- the production codec is implemented **independently**, from the normative
  document and the generated vectors — not by porting this code;
- it MUST reproduce every frozen vector in `generated/golden_vectors.md` and the
  corpus digest in `generated/golden_vectors.json` exactly;
- differential and round-trip tests compare production against this reference;
- **production code may NOT import this package.** `CHK_PRODUCTION_DOES_NOT_IMPORT_THE_REFERENCE_SPEC`
  scans `src/muster` for exactly that and fails the build.

That separation is the whole point. A production codec validated against a
reference it was copied from validates nothing — common-mode failure passes both
sides. Two independent implementations agreeing on 16 vectors and a corpus digest
is evidence.

## Layout

| Path | Role |
|---|---|
| `muster_spec/nodes.py` | the canonical value model and the **only** encoder/decoder |
| `muster_spec/schema.py` | the declarative schema language and validator |
| `muster_spec/registry.py` | **the single source of truth** — every Phase-1 wire type |
| `muster_spec/inventory.py` | the frozen explicit type allowlist |
| `muster_spec/digests.py` | domain separation, path salts, salted commitments |
| `muster_spec/signing.py` | signing bodies, verification, mutation generation |
| `muster_spec/relations.py` | the acquisition relation algebra and its lowering |
| `muster_spec/hinge.py` | `Term`/`QTerm` builders, lowering, the evaluator |
| `muster_spec/selfcomp.py` | query construction, S1 reference and S2 canonical semantics |
| `muster_spec/paths.py` | the frozen commitment-path inventory and total extractor |
| `muster_spec/merkle.py` | commitment tree, proofs, verification |
| `muster_spec/disclosure.py` | pinned policy resolution and participant views |
| `muster_spec/checks.py` | the machine checks and the dependency matrix |
| `muster_spec/fixtures.py` | concrete specimens (fixed test constants only) |
| `muster_spec/scenario.py` | the end-to-end ALPHA/PO-4471 worked example |
| `muster_spec/vectors.py` | golden vector generation |
| `z3_backend.py` | S3 — Z3 lowering, run under the isolated venv |
| `run_spec.py` | runs everything and writes `generated/` |

## Running

```
python -m pytest tests/ -q          # 244 tests
python run_spec.py                  # checks + vectors + reports
```

The Z3 differential (S3) needs the isolated venv at `../../.specvenv-z3`. It is a
throwaway created for this phase only; nothing in the repository depends on it,
and the suite skips S3 if it is absent.

## Cryptographic stand-in

Signatures use HMAC-SHA256 with fixed test secrets. What Phase 0.8 freezes is
**which octets each signature covers** and **where the authoritative signer
identity lives** — not the primitive. Production substitutes a real asymmetric
scheme over the identical preimage. The mutation suite (flip any covered field,
verification must fail) is algorithm-independent, which is why the stand-in is
adequate for the property being frozen and inadequate for anything else.

All salts, nonces and keys here are fixed constants for reproducibility. None of
them is a secret and none may ever appear in production.
