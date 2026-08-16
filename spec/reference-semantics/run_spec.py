"""Run every machine check, generate every artifact, write the reports.

NON-PRODUCTION SPECIFICATION MATERIAL.

    python run_spec.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from muster_spec import checks, vectors  # noqa: E402
from muster_spec import scenario as S  # noqa: E402
from muster_spec.registry import REG  # noqa: E402
from muster_spec.paths import INVENTORY  # noqa: E402
from muster_spec.schema import SELF_BODY, digest_kinds, render_grammar  # noqa: E402

OUT = Path(__file__).resolve().parent / "generated"


def schema_report() -> str:
    records = [d for d in REG if d.kind == "record"]
    unions = [d for d in REG if d.kind == "union"]
    aliases = [d for d in REG if d.kind == "alias"]
    kinds = digest_kinds(REG)

    lines = [
        "# MUSTER Phase 0.8 -- declarative schema inventory",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.  Generated from `muster_spec/registry.py`.",
        "",
        f"- types: **{len(REG.order)}**  ({len(records)} records, {len(unions)} unions, "
        f"{len(aliases)} aliases)",
        f"- digest kinds: **{len(kinds)}**, all distinct",
        f"- signed artifacts: **{len([d for d in REG if d.signing])}**",
        f"- commitment paths: **{len(INVENTORY)}** inventory entries",
        "",
        "## Record tags and arities",
        "",
        "| Type | Tag | Arity | Digest kind | Persistence |",
        "|---|---|---|---|---|",
    ]
    for d in records:
        lines.append(
            f"| `{d.name}` | `{d.tag}` | {d.arity} | "
            f"{'`' + d.digest_kind + '`' if d.digest_kind else '--'} | {d.persistence} |"
        )

    lines += ["", "## Unions", "", "| Type | Variants |", "|---|---|"]
    for d in unions:
        lines.append(f"| `{d.name}` | {', '.join('`' + v + '`' for v, _ in d.variants)} |")

    lines += ["", "## Digest kinds", "", "| Kind | Type |", "|---|---|"]
    for kind, owner in sorted(kinds.items()):
        lines.append(f"| `{kind}` | `{owner}` |")

    lines += [
        "",
        "## Uniqueness constraints",
        "",
        "| Type | Collection | Key |",
        "|---|---|---|",
    ]
    for d in REG:
        for coll, key in d.unique_by:
            lines.append(f"| `{d.name}` | `{coll}` | {', '.join('`' + k + '`' for k in key)} |")

    lines += ["", "## Full grammar", "", "```", render_grammar(REG), "```", ""]
    return "\n".join(lines)


def signing_report() -> str:
    lines = [
        "# MUSTER Phase 0.8 -- signing-body report",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.  Generated from the registry.",
        "",
        "Every signature covers a first-class, named type.  Where the signature",
        "covers 'the record itself', the preimage is a GENERATED body type with its",
        "own tag and digest kind -- not an informal 'record minus signature'.",
        "",
        "| Artifact | Signed preimage | Digest domain | Authoritative signer identity |",
        "|---|---|---|---|",
    ]
    for d in REG:
        spec = d.signing
        if spec is None:
            continue
        body = f"`{d.name}Body`" if spec.body == SELF_BODY else f"`{d.name}.{spec.body}`"
        lines.append(f"| `{d.name}` | {body} | `{spec.domain}` | `{spec.key_ref_path}` |")
    lines += [
        "",
        "`Signature` itself carries only `(alg, sig)`.  It holds no signer reference,",
        "so the payload and the wrapper have nothing to disagree about.",
        "",
        "No security-critical field sits outside a signed body.  The Phase 0.7",
        "`VerificationReceipt.revocation_snapshot` -- swappable without resigning --",
        "is gone; revocation is pinned once per rebuild in `AuthorizationContext`,",
        "which is itself inside the semantic `CaseRevision`.",
        "",
    ]
    return "\n".join(lines)


def commitment_report() -> str:
    lines = [
        "# MUSTER Phase 0.8 -- commitment and Merkle report",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.",
        "",
        "## Frozen path inventory (certificate_schema_version = 1)",
        "",
        "| Path | Declared type | Present when |",
        "|---|---|---|",
    ]
    for spec in INVENTORY:
        path = f"`{spec.path}.<64 hex>`" if spec.dynamic else f"`{spec.path}`"
        lines.append(f"| {path} | `{spec.type_name}` | {spec.presence} |")

    lines += [
        "",
        "The extractor is total: its output **is** the leaf set.  A tree whose paths",
        "differ from the extractor output is `IncompleteCommitmentSet`.  A path outside",
        "the inventory is `UnknownCommitmentPath`.  Dynamic segments are 64 hex",
        "characters of a domain-separated digest, so they are injective, charset-safe,",
        "fixed width, and do not leak the identifier of an undisclosed item.",
        "",
        "## The worked scenario",
        "",
        f"- committed leaves: **{len(S.TREE.leaves)}**",
        f"- merkle: `{S.TREE.merkle.hex()}`",
        f"- root: `{S.TREE.root.hex()}`",
        f"- case commitment (salted): `{S.CASE_COMMITMENT.hex()}`",
        f"- revision commitment (salted): `{S.REVISION_COMMITMENT.hex()}`",
        f"- revision semantic digest (private): `{S.REVISION_SEMANTIC_DIGEST.hex()}`",
        "",
        "The last two differ, and only the salted form appears in the envelope.  That",
        "is [B11]: a raw semantic digest is a deterministic function of inputs a",
        "participant may be able to enumerate, so publishing it turns the envelope",
        "into an oracle for private inputs.",
        "",
        "## Shapes",
        "",
        "```",
        "merkle(0) = SHA-256(\"muster/v1/MERKLE_EMPTY\" || 0x00)",
        "merkle(1) = L0                              -- not hashed again",
        "merkle(2) = node(L0, L1)",
        "merkle(3) = node(node(L0, L1), L2)          -- PROMOTION, never duplication",
        "merkle(4) = node(node(L0, L1), node(L2, L3))",
        "```",
        "",
        "Proofs verify at every size 1..8; a promoted node contributes no step.",
        "`leaf_count` is committed in `CommitmentRoot`, and tenant, case commitment,",
        "revision commitment and schema version are bound into **every leaf**, so",
        "transplantation fails at the leaf, not merely at the root.",
        "",
    ]
    return "\n".join(lines)


def checks_report(results: dict[str, list[str]]) -> str:
    passed, total = checks.summarise(results)
    lines = [
        "# MUSTER Phase 0.8 -- machine check report",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.",
        "",
        f"**{passed}/{total} checks pass.**",
        "",
        "Each check is separately proved falsifiable: `test_every_check_is_falsifiable`",
        "injects the defect each check exists to catch and asserts the check reports it.",
        "A check that cannot fail proves nothing.",
        "",
        "| Check | Result |",
        "|---|---|",
    ]
    for name, failures in sorted(results.items()):
        lines.append(f"| `{name}` | {'PASS' if not failures else 'FAIL: ' + '; '.join(failures)} |")
    lines.append("")
    return "\n".join(lines)


def dependency_report() -> str:
    lines = [
        "# MUSTER Phase 0.8 -- dependency report",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.",
        "",
        "`forbidden(M) = AllModules \\ ({M} u allowed(M))`, computed -- never hand-listed.",
        "",
        "| Module | May import | Forbidden |",
        "|---|---|---|",
    ]
    for m in checks.MODULES:
        allowed = ", ".join(f"`{x}`" for x in checks.ALLOWED[m]) or "-- (nothing in muster)"
        forb = ", ".join(f"`{x}`" for x in sorted(checks.forbidden(m)))
        lines.append(f"| `{m}` | {allowed} | {forb} |")
    lines += [
        "",
        f"All **{len(checks.MODULES)}** modules have a row.  Phase 0.7 had ten rows for",
        "eleven modules: `application` was missing, so its claimed coverage was false",
        "and, read literally, nothing was permitted to construct `Z3Backend`.",
        "",
        "- `hinge` may import `solve` but neither adapter.",
        "- `solve` does not import its own adapters.",
        "- `application` -- the composition root, and only it -- may see `solve.z3`.",
        "- `evidence` may not import a domain; the domains are independent of each other.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    OUT.mkdir(exist_ok=True)
    results = checks.run_all()
    passed, total = checks.summarise(results)

    problems = vectors.verify_all()
    vectors.write()

    (OUT / "schema_inventory.md").write_text(schema_report(), encoding="utf-8")
    (OUT / "signing_report.md").write_text(signing_report(), encoding="utf-8")
    (OUT / "commitment_report.md").write_text(commitment_report(), encoding="utf-8")
    (OUT / "checks_report.md").write_text(checks_report(results), encoding="utf-8")
    (OUT / "dependency_report.md").write_text(dependency_report(), encoding="utf-8")

    print(f"checks           : {passed}/{total} pass")
    print(f"types            : {len(REG.order)}")
    print(f"digest kinds     : {len(digest_kinds(REG))}")
    print(f"signed artifacts : {len([d for d in REG if d.signing])}")
    print(f"commitment paths : {len(INVENTORY)} inventory entries, {len(S.TREE.leaves)} leaves")
    print(f"golden vectors   : {len(vectors.vectors())} ({'OK' if not problems else problems})")
    print(f"corpus digest    : {vectors.corpus_digest()}")
    for name, failures in sorted(results.items()):
        if failures:
            print(f"FAIL {name}")
            for f in failures:
                print(f"     {f}")
    return 0 if (passed == total and not problems) else 1


if __name__ == "__main__":
    raise SystemExit(main())
