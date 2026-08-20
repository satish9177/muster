"""Signing bodies, verification and mutation testing.

NON-PRODUCTION SPECIFICATION MATERIAL.

The algorithm here is HMAC-SHA256 with per-key-reference secrets.  That is a
deliberate stand-in: what Phase 0.8 freezes is *which octets each signature
covers* and *where the authoritative signer identity lives*, not the primitive.
Production M1 substitutes a real asymmetric scheme over the identical preimage.
The mutation suite -- flip any covered field, verification must fail -- is
algorithm-independent and is the property actually being frozen.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .digests import digest_bytes
from .nodes import Atom, Bytes, Node, Rec, Tagged, encode
from .registry import REG
from .schema import SELF_BODY, Registry, SchemaError, TypeDecl

SIG_ALG = "HMAC-SHA256-SPEC-STANDIN"


class SigningError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Keyring:
    """Maps a signer key reference to its secret.  Stand-in for a key registry."""

    secrets: dict[str, bytes]

    def secret(self, key_ref: str) -> bytes:
        try:
            return self.secrets[key_ref]
        except KeyError as exc:
            raise SigningError(f"unknown signer key reference {key_ref!r}") from exc

    #  ``snapshot_digest`` is GONE, with the KEY_REGISTRY_SNAPSHOT domain it
    #  computed.  Its preimage was ``key_ref || 0x00 || SHA-256(key material)``,
    #  so the only question it could answer was "does this key exist" -- and the
    #  question that decides admissibility is "may this key say this, here,
    #  now".  An AuthorizationContext now pins an AuthorityRegistrySnapshot,
    #  which is a declared type with its own domain; see ``scenario`` for the
    #  worked one.  Keeping a second, weaker authority preimage alive beside it
    #  would be a downgrade path rather than a convenience.


# --------------------------------------------------------------------------
# body extraction
# --------------------------------------------------------------------------


def field_index(decl: TypeDecl, name: str) -> int:
    names = [f.name for f in decl.fields]
    if name not in names:
        raise SigningError(f"{decl.name} has no field {name!r}")
    return names.index(name)


def resolve_path(reg: Registry, node: Node, decl: TypeDecl, path: str) -> Node:
    cursor: Node = node
    cdecl = decl
    for step in path.split("."):
        while isinstance(cursor, Tagged):
            cursor = cursor.value
        if not isinstance(cursor, Rec):
            raise SigningError(f"cannot resolve {path!r}: hit {type(cursor).__name__}")
        cdecl = _decl_for_tag(reg, cursor.tag)
        idx = field_index(cdecl, step)
        cursor = cursor.fields[idx]
        nxt = reg.resolve(cdecl.fields[idx].type)
        from .schema import Ref as _Ref

        if isinstance(nxt, _Ref):
            cdecl = reg[nxt.name]
    return cursor


def _decl_for_tag(reg: Registry, tag: str) -> TypeDecl:
    for d in reg:
        if d.kind == "record" and d.tag == tag:
            return d
    raise SigningError(f"no declaration for record tag {tag!r}")


def signing_body(reg: Registry, node: Rec, decl: TypeDecl) -> tuple[str, Node]:
    """Return (digest domain, the exact node whose canonical encoding is signed)."""
    spec = decl.signing
    if spec is None:
        raise SigningError(f"{decl.name} is not a signed artifact")
    if spec.body == SELF_BODY:
        body_decl = reg[f"{decl.name}Body"]
        sig_idx = field_index(decl, spec.signature_field)
        fields = [f for i, f in enumerate(node.fields) if i != sig_idx]
        assert body_decl.tag is not None
        return spec.domain, Rec(body_decl.tag, fields)
    return spec.domain, node.fields[field_index(decl, spec.body)]


def signer_key_ref(reg: Registry, node: Rec, decl: TypeDecl) -> str:
    spec = decl.signing
    if spec is None:
        raise SigningError(f"{decl.name} is not a signed artifact")
    found = resolve_path(reg, node, decl, spec.key_ref_path)
    if not isinstance(found, Atom):
        raise SigningError(f"{decl.name}.{spec.key_ref_path} is not an ATOM")
    return found.value


def key_ref_is_inside_body(reg: Registry, node: Rec, decl: TypeDecl) -> bool:
    """[B5] The signer identity must be covered by the signature it authorises."""
    _, body = signing_body(reg, node, decl)
    spec = decl.signing
    assert spec is not None
    needle = encode(Atom(signer_key_ref(reg, node, decl)))
    return needle in encode(body)


# --------------------------------------------------------------------------
# sign / verify
# --------------------------------------------------------------------------


def sign_body(secret: bytes, domain: str, body: Node) -> Bytes:
    preimage = digest_bytes(domain, encode(body))
    return Bytes(hmac.new(secret, preimage, hashlib.sha256).digest())


def make_signature(secret: bytes, domain: str, body: Node) -> Rec:
    return Rec("Signature/v1", [Atom(SIG_ALG), sign_body(secret, domain, body)])


def sign_record(reg: Registry, keyring: Keyring, node: Rec, type_name: str) -> Rec:
    """Return `node` with its signature field replaced by a valid signature."""
    decl = reg[type_name]
    spec = decl.signing
    if spec is None:
        raise SigningError(f"{type_name} is not a signed artifact")
    key_ref = signer_key_ref(reg, node, decl)
    domain, body = signing_body(reg, node, decl)
    sig = make_signature(keyring.secret(key_ref), domain, body)
    idx = field_index(decl, spec.signature_field)
    fields = list(node.fields)
    fields[idx] = sig
    return Rec(node.tag, fields)


def verify_record(reg: Registry, keyring: Keyring, node: Rec, type_name: str) -> bool:
    decl = reg[type_name]
    spec = decl.signing
    if spec is None:
        raise SigningError(f"{type_name} is not a signed artifact")
    sig_node = node.fields[field_index(decl, spec.signature_field)]
    if not isinstance(sig_node, Rec) or sig_node.tag != "Signature/v1":
        return False
    alg, raw = sig_node.fields
    if not isinstance(alg, Atom) or alg.value != SIG_ALG:
        return False
    if not isinstance(raw, Bytes):
        return False
    try:
        key_ref = signer_key_ref(reg, node, decl)
        secret = keyring.secret(key_ref)
    except SigningError:
        return False
    domain, body = signing_body(reg, node, decl)
    return hmac.compare_digest(raw.value, sign_body(secret, domain, body).value)


# --------------------------------------------------------------------------
# mutation testing -- every covered octet position must be load-bearing
# --------------------------------------------------------------------------


def mutations(node: Node) -> list[tuple[str, Node]]:
    """Yield (description, mutated node) for every leaf position in `node`."""
    out: list[tuple[str, Node]] = []

    def walk(cur: Node, path: str) -> None:
        from .nodes import Bool, Digest, Int, Seq, SetV, Unit

        if isinstance(cur, Atom):
            out.append((path, _replace(node, path, Atom(_perturb_atom(cur.value)))))
        elif isinstance(cur, Int):
            out.append((path, _replace(node, path, Int(cur.value + 1))))
        elif isinstance(cur, Bool):
            out.append((path, _replace(node, path, Bool(not cur.value))))
        elif isinstance(cur, Bytes):
            out.append((path, _replace(node, path, Bytes(_perturb_bytes(cur.value)))))
        elif isinstance(cur, Digest):
            out.append((path, _replace(node, path, Digest(_perturb_bytes(cur.raw)))))
        elif isinstance(cur, Unit):
            pass
        elif isinstance(cur, Rec):
            for i, f in enumerate(cur.fields):
                walk(f, f"{path}/{i}")
        elif isinstance(cur, Tagged):
            walk(cur.value, f"{path}/*")
        elif isinstance(cur, (Seq, SetV)):
            for i, f in enumerate(cur.items):
                walk(f, f"{path}/{i}")

    walk(node, "")
    return out


def _perturb_atom(value: str) -> str:
    return value[:-1] + ("X" if value[-1] != "X" else "Y")


def _perturb_bytes(value: bytes) -> bytes:
    if not value:
        return b"\x01"
    return value[:-1] + bytes([value[-1] ^ 0x01])


def _replace(root: Node, path: str, new: Node) -> Node:
    steps = [s for s in path.split("/") if s != ""]

    def rec(cur: Node, rest: list[str]) -> Node:
        from .nodes import Seq, SetV

        if not rest:
            return new
        head, tail = rest[0], rest[1:]
        if head == "*":
            assert isinstance(cur, Tagged)
            return Tagged(cur.variant, rec(cur.value, tail))
        i = int(head)
        if isinstance(cur, Rec):
            fields = list(cur.fields)
            fields[i] = rec(fields[i], tail)
            return Rec(cur.tag, fields)
        if isinstance(cur, Seq):
            items = list(cur.items)
            items[i] = rec(items[i], tail)
            return Seq(items)
        if isinstance(cur, SetV):
            items = list(cur.items)
            items[i] = rec(items[i], tail)
            return SetV(items)
        raise SigningError(f"cannot descend into {type(cur).__name__}")

    return rec(root, steps)


__all__ = [
    "Keyring",
    "SigningError",
    "SIG_ALG",
    "key_ref_is_inside_body",
    "make_signature",
    "mutations",
    "resolve_path",
    "sign_record",
    "signer_key_ref",
    "signing_body",
    "verify_record",
]
