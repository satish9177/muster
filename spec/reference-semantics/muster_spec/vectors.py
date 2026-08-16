"""Golden vector generation.  Nothing here is hand-transcribed.

NON-PRODUCTION SPECIFICATION MATERIAL.

Every length octet, every digest and every hex string below is computed by the
reference encoder from the specimens in fixtures.py and scenario.py.  Phase 0.7
hand-wrote its vectors and got four ATOM length octets wrong; hand-transcription
is not a thing to do more carefully, it is a thing to stop doing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import fixtures as F
from . import scenario as S
from .digests import digest_bytes, digest_node
from .hinge import T
from .nodes import Atom, Int, Node, Rec, Tagged, decode, encode, hexdump
from .registry import REG
from .schema import Ref, validate
from .selfcomp import build_sufficiency_query
from .signing import signing_body

OUT = Path(__file__).resolve().parents[1] / "generated"


@dataclass(frozen=True, slots=True)
class Vector:
    name: str
    type_name: str
    node: Node
    digest_kind: str | None
    note: str = ""

    @property
    def octets(self) -> bytes:
        return encode(self.node)

    @property
    def hex(self) -> str:
        return self.octets.hex()

    @property
    def digest(self) -> str | None:
        if self.digest_kind is None:
            return None
        return digest_bytes(self.digest_kind, self.octets).hex()


NESTED_TERM = T.ge(T.var(F.Q_REF), T.lit(("int", 97)))

A1_CASE = F.a1_case()
A1_QUERY = build_sufficiency_query(
    A1_CASE, [A1_CASE.universe[0]], digest_node("LOGICAL_CASE", Atom("a1"))
)

RECEIPT_DOMAIN, RECEIPT_BODY = signing_body(
    REG, S.VERIFICATION_RECEIPT, REG["VerificationReceipt"]
)


def vectors() -> list[Vector]:
    return [
        Vector("V-01-SymbolRef", "SymbolRef", F.Q_REF, "SYMBOL_REF",
               "accepted_quantity(PO-4471)"),
        Vector("V-02-NestedTerm", "Term", NESTED_TERM, "TERM",
               "Ge(Var(accepted_quantity(PO-4471)), LitInt(97))"),
        Vector("V-03-SolverQuery", "SolverQuery", A1_QUERY, "SOLVER_QUERY",
               "[A1] the mandatory counterexample, S = {q}: contains LEFT and RIGHT "
               "QueryVar leaves and a cross-world FIX assertion"),
        Vector("V-04-Action", "Action", F.PAY_ACTION, "ACTION",
               "PAY(recipient=SUP-12, amount=INR 63000.00, basis_code=FIXED)"),
        Vector("V-05-ConsequentialAction", "ConsequentialAction", F.PAY_CONSEQUENTIAL,
               "CONSEQUENTIAL_ACTION", "project(V-04): basis_code is DIAGNOSTIC and is dropped"),
        Vector("V-06-AcquisitionPayload", "AcquisitionPayload", S.ACQUISITION_PAYLOAD,
               "ATTESTATION_PAYLOAD", "ClosedLowerBound(accepted_quantity, 99)"),
        Vector("V-07-VerificationReceiptSigningBody", "AcquisitionPayload", RECEIPT_BODY,
               RECEIPT_DOMAIN, "[B5] the EXACT octets the receipt signature covers"),
        Vector("V-08-InterestAssessment", "InterestAssessment", S.INTEREST_ASSESSMENT,
               "INTEREST_ASSESSMENT", ""),
        Vector("V-09-CaseRevision", "CaseRevision", S.CASE_REVISION, "CASE_REVISION",
               "[A3] carries mode and authorization_context_digest"),
        Vector("V-10-BundleManifest", "BundleManifest", S.BUNDLE_MANIFEST, "MANIFEST", ""),
        Vector("V-11-DisclosurePolicy", "DisclosurePolicy", S.DISCLOSURE_POLICY,
               "DISCLOSURE_POLICY", "[N1] three entries, keyed by outcome_class"),
        Vector("V-12-CommitmentEnvelope", "CommitmentEnvelope", S.COMMITMENT_ENVELOPE,
               "COMMITMENT_ENVELOPE", "[B8/B11] signed, and both commitments are salted"),
        Vector("V-13-SignedCommitmentEnvelope", "SignedCommitmentEnvelope", S.SIGNED_ENVELOPE,
               None, "[B8] the authenticated form a participant actually receives"),
        Vector("V-14-ParticipantView", "ParticipantView", S.WAREHOUSE_VIEW, "PARTICIPANT_VIEW",
               "WAREHOUSE / NOTIFICATION on a DIVERGENT outcome"),
        Vector("V-15-CommitmentLeaf", "CommitmentLeaf",
               Rec("CommitmentLeaf/v1", [
                   Atom(F.TENANT), S.CASE_COMMITMENT, S.REVISION_COMMITMENT, Int(1),
                   Atom(S.TREE.paths[0]),
                   __import__("muster_spec.nodes", fromlist=["Bytes"]).Bytes(S.TREE.salts[0]),
                   __import__("muster_spec.nodes", fromlist=["Bytes"]).Bytes(S.TREE.values[0]),
               ]), "MERKLE_LEAF", f"path {S.TREE.paths[0]}"),
        Vector("V-16-CommitmentRoot", "CommitmentRoot", S.TREE.root_node, "MERKLE_ROOT",
               f"{len(S.TREE.leaves)} leaves"),
    ]


def verify_all() -> list[str]:
    """Every vector must validate, round-trip and re-encode identically."""
    problems = []
    for v in vectors():
        try:
            validate(REG, v.node, Ref(v.type_name))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{v.name}: schema validation failed: {exc}")
        raw = v.octets
        if encode(decode(raw)) != raw:
            problems.append(f"{v.name}: not canonical under decode/encode")
        if decode(raw) != v.node:
            problems.append(f"{v.name}: round-trip changed the value")
        if "..." in v.hex or "…" in v.note:
            problems.append(f"{v.name}: placeholder in output")
    return problems


def corpus_digest() -> str:
    """One digest over the whole frozen corpus.

    M1's independently written production codec must reproduce this exact value.
    """
    material = b"".join(
        v.name.encode("ascii") + b"\x00" + v.octets + b"\x00" for v in vectors()
    )
    return digest_bytes("GOLDEN_VECTOR_CORPUS", material).hex()


def to_json() -> str:
    return json.dumps(
        {
            "corpus_digest": corpus_digest(),
            "vectors": [
                {
                    "name": v.name,
                    "type": v.type_name,
                    "note": v.note,
                    "octet_length": len(v.octets),
                    "hex": v.hex,
                    "digest_kind": v.digest_kind,
                    "digest": v.digest,
                }
                for v in vectors()
            ],
        },
        indent=2,
        sort_keys=True,
    )


def to_markdown() -> str:
    lines = [
        "# MUSTER Phase 0.8 -- generated golden vectors",
        "",
        "NON-PRODUCTION SPECIFICATION MATERIAL.  Generated by the reference encoder;",
        "no octet below was typed by hand.",
        "",
        f"Corpus digest: `{corpus_digest()}`",
        "",
        "M1's production codec is written independently and must reproduce every",
        "vector and this corpus digest exactly.  It may not import the reference",
        "encoder that produced them.",
        "",
    ]
    for v in vectors():
        lines += [
            f"## {v.name}",
            "",
            f"- type: `{v.type_name}`",
            f"- octets: {len(v.octets)}",
        ]
        if v.note:
            lines.append(f"- note: {v.note}")
        if v.digest_kind:
            lines.append(f"- `digest({v.digest_kind}, .)` = `{v.digest}`")
        lines += ["", "```", *_wrap(hexdump(v.octets)), "```", ""]
    return "\n".join(lines)


def _wrap(text: str, width: int = 72) -> list[str]:
    out, line = [], ""
    for token in text.split(" "):
        if len(line) + len(token) + 1 > width:
            out.append(line)
            line = token
        else:
            line = f"{line} {token}".strip()
    if line:
        out.append(line)
    return out


def write() -> tuple[Path, Path]:
    OUT.mkdir(exist_ok=True)
    md, js = OUT / "golden_vectors.md", OUT / "golden_vectors.json"
    md.write_text(to_markdown(), encoding="utf-8")
    js.write_text(to_json(), encoding="utf-8")
    return md, js
