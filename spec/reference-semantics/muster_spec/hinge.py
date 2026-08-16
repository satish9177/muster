"""World-qualified query construction and three independent semantics.

NON-PRODUCTION SPECIFICATION MATERIAL.

[A1] closes the Phase 0.7 defect in which the canonical query representation
could not express its own semantics: `Term.Var` carried a bare `SymbolRef`, and
`LabeledAssertion.side` assigned one side to a whole formula, so neither
`FIX: q_L = q_R` nor `DIFF: proj(A_L) != proj(A_R)` was representable.

Three semantics are computed and required to agree:

  S1  bounded reference   -- enumerates worlds and runs the policy concretely.
                             Never constructs a query at all.
  S2  canonical query     -- encodes the SolverQuery, DECODES it back from
                             octets, and enumerates the declared variables.
                             Knows nothing about "worlds": (S,q), (L,q) and
                             (R,q) are three independent variables, which is
                             exactly what makes a world collapse observable.
  S3  Z3 lowering         -- decodes the same octets and lowers to Z3.
                             See z3_backend.py.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Callable, Hashable, Iterable, Iterator, Sequence

from .digests import digest_node
from .nodes import Atom, Bool, Bytes, Digest, Int, Node, Rec, Seq, SetV, Tagged, Unit, encode

ENUM_CAP = 200_000


class LoweringError(Exception):
    pass


class EvalError(Exception):
    pass


# --------------------------------------------------------------------------
# values
# --------------------------------------------------------------------------

Val = tuple  # ("bool", b) | ("int", n) | ("scaled", unit, scale, minor) | ("enum", eid, m)


def v_bool(b: bool) -> Val:
    return ("bool", b)


def v_int(n: int) -> Val:
    return ("int", n)


def v_scaled(unit: str, scale: int, minor: int) -> Val:
    return ("scaled", unit, scale, minor)


def v_enum(enum_id: str, member: str) -> Val:
    return ("enum", enum_id, member)


def val_to_node(v: Val) -> Node:
    if v[0] == "bool":
        return Tagged("VBool", Bool(v[1]))
    if v[0] == "int":
        return Tagged("VInt", Int(v[1]))
    if v[0] == "scaled":
        return Tagged("VScaled", Rec("VScaled/v1", [Atom(v[1]), Int(v[2]), Int(v[3])]))
    if v[0] == "enum":
        return Tagged("VEnum", Rec("VEnum/v1", [Atom(v[1]), Atom(v[2])]))
    raise EvalError(f"unrepresentable value {v!r}")


def node_to_val(node: Node) -> Val:
    if not isinstance(node, Tagged):
        raise EvalError("Value must be TAGGED")
    if node.variant == "VBool":
        assert isinstance(node.value, Bool)
        return v_bool(node.value.value)
    if node.variant == "VInt":
        assert isinstance(node.value, Int)
        return v_int(node.value.value)
    if node.variant == "VScaled":
        assert isinstance(node.value, Rec)
        u, s, m = node.value.fields
        return v_scaled(u.value, s.value, m.value)  # type: ignore[union-attr]
    if node.variant == "VEnum":
        assert isinstance(node.value, Rec)
        e, m = node.value.fields
        return v_enum(e.value, m.value)  # type: ignore[union-attr]
    raise EvalError(f"unknown Value variant {node.variant}")


def filler(sort: Node) -> Val:
    """Derived, never authored.  B2 proves it is never read on a live branch."""
    assert isinstance(sort, Tagged)
    if sort.variant == "Bool":
        return v_bool(False)
    if sort.variant == "Int":
        return v_int(0)
    if sort.variant == "Scaled":
        assert isinstance(sort.value, Rec)
        return v_scaled(sort.value.fields[0].value, sort.value.fields[1].value, 0)  # type: ignore[union-attr]
    if sort.variant == "Enum":
        raise LoweringError("enum filler requires the declared domain, use filler_for_domain")
    raise LoweringError(f"no filler for sort {sort.variant}")


def filler_for(sort: Node, domain: Node) -> Val:
    assert isinstance(sort, Tagged)
    if sort.variant == "Enum":
        assert isinstance(domain, Tagged) and domain.variant == "EnumDomain"
        assert isinstance(domain.value, Rec)
        members = domain.value.fields[0]
        assert isinstance(members, Seq)
        first = members.items[0]
        assert isinstance(first, Atom)
        assert isinstance(sort.value, Rec)
        return v_enum(sort.value.fields[0].value, first.value)  # type: ignore[union-attr]
    return filler(sort)


# --------------------------------------------------------------------------
# term builders, parameterised by family
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TermBuilder:
    """`prefix=""` builds `Term` (policy IR); `prefix="Q"` builds `QTerm`."""

    prefix: str = ""

    def _bin(self, variant: str, a: Node, b: Node) -> Node:
        return Tagged(variant, Rec(f"{self.prefix}Bin/v1", [a, b]))

    def var(self, ref: Node, side: str | None = None) -> Node:
        if self.prefix == "":
            if side is not None:
                raise LoweringError("policy IR Var cannot carry a world side")
            return Tagged("Var", ref)
        if side is None:
            raise LoweringError("QTerm leaf requires a world side")
        return Tagged("QVar", Rec("QueryVar/v1", [Atom(side), ref]))

    def lit(self, v: Val) -> Node:
        if v[0] == "bool":
            return Tagged("LitBool", Bool(v[1]))
        if v[0] == "int":
            return Tagged("LitInt", Int(v[1]))
        if v[0] == "scaled":
            return Tagged("LitScaled", Rec("VScaled/v1", [Atom(v[1]), Int(v[2]), Int(v[3])]))
        if v[0] == "enum":
            return Tagged("LitEnum", Rec("VEnum/v1", [Atom(v[1]), Atom(v[2])]))
        raise LoweringError(f"no literal for {v!r}")

    def not_(self, a: Node) -> Node:
        return Tagged("Not", a)

    def neg(self, a: Node) -> Node:
        return Tagged("Neg", a)

    def _nary(self, variant: str, xs: Sequence[Node]) -> Node:
        items = list(xs)
        if len(items) == 0:
            raise LoweringError(f"{variant} requires at least one operand")
        if len(items) == 1:
            return items[0]
        return Tagged(variant, Seq(items))

    def and_(self, *xs: Node) -> Node:
        return self._nary("And", xs)

    def or_(self, *xs: Node) -> Node:
        return self._nary("Or", xs)

    def add(self, *xs: Node) -> Node:
        return self._nary("Add", xs)

    def implies(self, a: Node, b: Node) -> Node:
        return self._bin("Implies", a, b)

    def iff(self, a: Node, b: Node) -> Node:
        return self._bin("Iff", a, b)

    def sub(self, a: Node, b: Node) -> Node:
        return self._bin("Sub", a, b)

    def eq(self, a: Node, b: Node) -> Node:
        return self._bin("Eq", a, b)

    def ne(self, a: Node, b: Node) -> Node:
        return self._bin("Ne", a, b)

    def lt(self, a: Node, b: Node) -> Node:
        return self._bin("Lt", a, b)

    def le(self, a: Node, b: Node) -> Node:
        return self._bin("Le", a, b)

    def gt(self, a: Node, b: Node) -> Node:
        return self._bin("Gt", a, b)

    def ge(self, a: Node, b: Node) -> Node:
        return self._bin("Ge", a, b)

    def mulconst(self, k: int, a: Node) -> Node:
        return Tagged("MulConst", Rec(f"{self.prefix}MulConst/v1", [Int(k), a]))

    def ite(self, c: Node, t: Node, f: Node) -> Node:
        return Tagged("Ite", Rec(f"{self.prefix}Ite/v1", [c, t, f]))


T = TermBuilder("")
Q = TermBuilder("Q")


# --------------------------------------------------------------------------
# lowering: Term -> QTerm under a world environment
# --------------------------------------------------------------------------

#: An environment maps a policy symbol to the world side its occurrence denotes.
Env = Callable[[Node], str]


def env_shared() -> Env:
    return lambda ref: "S"


def env_world(side: str, known: frozenset[bytes]) -> Env:
    """[A1] Known values are SHARED between the worlds; unresolved values are not.

    This is what makes "shared known K values on both worlds" structural rather
    than an extra assertion that an implementation could forget.
    """

    def env(ref: Node) -> str:
        return "S" if encode(ref) in known else side

    return env


def lower(term: Node, env: Env) -> Node:
    """lower(term, environment) -- total, structure preserving, leaf rewriting."""
    if not isinstance(term, Tagged):
        raise LoweringError(f"Term must be TAGGED, got {type(term).__name__}")
    v = term.variant

    if v == "Var":
        return Q.var(term.value, env(term.value))
    if v == "QVar":
        raise LoweringError("cannot lower a QTerm: policy IR must not contain QVar")
    if v in ("LitBool", "LitInt", "LitScaled", "LitEnum"):
        return term
    if v in ("Not", "Neg"):
        return Tagged(v, lower(term.value, env))
    if v in ("And", "Or", "Add"):
        assert isinstance(term.value, Seq)
        return Tagged(v, Seq([lower(x, env) for x in term.value.items]))
    if v in ("Implies", "Iff", "Sub", "Eq", "Ne", "Lt", "Le", "Gt", "Ge"):
        assert isinstance(term.value, Rec)
        a, b = term.value.fields
        return Tagged(v, Rec("QBin/v1", [lower(a, env), lower(b, env)]))
    if v == "MulConst":
        assert isinstance(term.value, Rec)
        k, a = term.value.fields
        return Tagged(v, Rec("QMulConst/v1", [k, lower(a, env)]))
    if v == "Ite":
        assert isinstance(term.value, Rec)
        c, t, f = term.value.fields
        return Tagged(v, Rec("QIte/v1", [lower(c, env), lower(t, env), lower(f, env)]))
    if v == "Rescale":
        assert isinstance(term.value, Rec)
        a, s = term.value.fields
        return Tagged(v, Rec("QRescale/v1", [lower(a, env), s]))
    if v == "Scale":
        assert isinstance(term.value, Rec)
        a, k, to = term.value.fields
        return Tagged(v, Rec("QScale/v1", [lower(a, env), k, to]))
    if v == "EnumTable":
        assert isinstance(term.value, Rec)
        scrut, arms = term.value.fields
        assert isinstance(arms, Seq)
        new_arms = []
        for arm in arms.items:
            assert isinstance(arm, Rec)
            m, t = arm.fields
            new_arms.append(Rec("QArm/v1", [m, lower(t, env)]))
        return Tagged(v, Rec("QEnumTable/v1", [lower(scrut, env), Seq(new_arms)]))
    raise LoweringError(f"unknown Term variant {v!r}")


# --------------------------------------------------------------------------
# evaluator -- shared by every family, parameterised by leaf key extraction
# --------------------------------------------------------------------------

LeafKey = Callable[[Node], Hashable]


def term_leaf_key(node: Node) -> Hashable:
    return encode(node)


def qterm_leaf_key(node: Node) -> Hashable:
    assert isinstance(node, Rec) and node.tag == "QueryVar/v1"
    side, ref = node.fields
    assert isinstance(side, Atom)
    return (side.value, encode(ref))


def evaluate(term: Node, assignment: dict[Hashable, Val], leaf_key: LeafKey) -> Val:
    if not isinstance(term, Tagged):
        raise EvalError("term must be TAGGED")
    v = term.variant
    ev = lambda t: evaluate(t, assignment, leaf_key)  # noqa: E731

    if v in ("Var", "QVar"):
        key = leaf_key(term.value)
        if key not in assignment:
            raise EvalError(f"open term: no assignment for {key!r}")
        return assignment[key]
    if v == "LitBool":
        return v_bool(term.value.value)  # type: ignore[union-attr]
    if v == "LitInt":
        return v_int(term.value.value)  # type: ignore[union-attr]
    if v in ("LitScaled", "LitEnum"):
        return node_to_val(Tagged("VScaled" if v == "LitScaled" else "VEnum", term.value))
    if v == "Not":
        return v_bool(not _b(ev(term.value)))
    if v == "Neg":
        return _arith_neg(ev(term.value))
    if v in ("And", "Or"):
        assert isinstance(term.value, Seq)
        vals = [_b(ev(x)) for x in term.value.items]
        return v_bool(all(vals) if v == "And" else any(vals))
    if v == "Add":
        assert isinstance(term.value, Seq)
        acc = ev(term.value.items[0])
        for x in term.value.items[1:]:
            acc = _arith(acc, ev(x), lambda a, b: a + b)
        return acc
    if v in ("Implies", "Iff", "Sub", "Eq", "Ne", "Lt", "Le", "Gt", "Ge"):
        assert isinstance(term.value, Rec)
        a, b = (ev(x) for x in term.value.fields)
        return _binop(v, a, b)
    if v == "MulConst":
        assert isinstance(term.value, Rec)
        k, a = term.value.fields
        assert isinstance(k, Int)
        return _arith_scale(ev(a), k.value)
    if v == "Ite":
        assert isinstance(term.value, Rec)
        c, t, f = term.value.fields
        return ev(t) if _b(ev(c)) else ev(f)
    if v == "EnumTable":
        assert isinstance(term.value, Rec)
        scrut, arms = term.value.fields
        s = ev(scrut)
        if s[0] != "enum":
            raise EvalError("EnumTable scrutinee is not an enum")
        assert isinstance(arms, Seq)
        for arm in arms.items:
            assert isinstance(arm, Rec)
            m, t = arm.fields
            assert isinstance(m, Atom)
            if m.value == s[2]:
                return ev(t)
        raise EvalError(f"EnumTable is not total for member {s[2]!r}")
    raise EvalError(f"unknown variant {v!r}")


def _b(v: Val) -> bool:
    if v[0] != "bool":
        raise EvalError(f"expected Bool, got {v[0]}")
    return bool(v[1])


def _numeric(v: Val) -> int:
    if v[0] == "int":
        return int(v[1])
    if v[0] == "scaled":
        return int(v[3])
    raise EvalError(f"expected numeric, got {v[0]}")


def _arith(a: Val, b: Val, op: Callable[[int, int], int]) -> Val:
    if a[0] == "int" and b[0] == "int":
        return v_int(op(a[1], b[1]))
    if a[0] == "scaled" and b[0] == "scaled":
        if a[1] != b[1] or a[2] != b[2]:
            raise EvalError(f"unit/scale mismatch {a[1]}@{a[2]} vs {b[1]}@{b[2]}")
        return v_scaled(a[1], a[2], op(a[3], b[3]))
    raise EvalError(f"cannot combine {a[0]} and {b[0]}")


def _arith_neg(a: Val) -> Val:
    if a[0] == "int":
        return v_int(-a[1])
    if a[0] == "scaled":
        return v_scaled(a[1], a[2], -a[3])
    raise EvalError("Neg on non-numeric")


def _arith_scale(a: Val, k: int) -> Val:
    if a[0] == "int":
        return v_int(a[1] * k)
    if a[0] == "scaled":
        return v_scaled(a[1], a[2], a[3] * k)
    raise EvalError("MulConst on non-numeric")


def _binop(op: str, a: Val, b: Val) -> Val:
    if op == "Implies":
        return v_bool((not _b(a)) or _b(b))
    if op == "Iff":
        return v_bool(_b(a) == _b(b))
    if op == "Sub":
        return _arith(a, b, lambda x, y: x - y)
    if op in ("Eq", "Ne"):
        if a[0] != b[0]:
            raise EvalError(f"cannot compare {a[0]} with {b[0]}")
        if a[0] in ("enum",) and a[1] != b[1]:
            raise EvalError("enum identity mismatch")
        if a[0] == "scaled" and (a[1] != b[1] or a[2] != b[2]):
            raise EvalError("unit/scale mismatch in comparison")
        same = a == b
        return v_bool(same if op == "Eq" else not same)
    x, y = _numeric(a), _numeric(b)
    if a[0] == "scaled" and b[0] == "scaled" and (a[1] != b[1] or a[2] != b[2]):
        raise EvalError("unit/scale mismatch in ordering")
    return v_bool(
        {"Lt": x < y, "Le": x <= y, "Gt": x > y, "Ge": x >= y}[op]
    )


# --------------------------------------------------------------------------
# domains
# --------------------------------------------------------------------------


def domain_values(sort: Node, domain: Node) -> list[Val]:
    assert isinstance(domain, Tagged) and isinstance(sort, Tagged)
    if domain.variant == "BoolDomain":
        return [v_bool(False), v_bool(True)]
    if domain.variant == "IntRange":
        assert isinstance(domain.value, Rec)
        lo, hi = domain.value.fields
        return [v_int(n) for n in range(lo.value, hi.value + 1)]  # type: ignore[union-attr]
    if domain.variant == "ScaledRange":
        assert isinstance(domain.value, Rec) and isinstance(sort.value, Rec)
        lo, hi = domain.value.fields
        unit, scale = sort.value.fields
        return [
            v_scaled(unit.value, scale.value, n)  # type: ignore[union-attr]
            for n in range(lo.value, hi.value + 1)  # type: ignore[union-attr]
        ]
    if domain.variant == "EnumDomain":
        assert isinstance(domain.value, Rec) and isinstance(sort.value, Rec)
        members = domain.value.fields[0]
        assert isinstance(members, Seq)
        eid = sort.value.fields[0]
        assert isinstance(eid, Atom)
        return [v_enum(eid.value, m.value) for m in members.items]  # type: ignore[union-attr]
    raise EvalError(f"unknown domain {domain.variant}")


def product(spaces: Sequence[tuple[Hashable, list[Val]]]) -> Iterator[dict[Hashable, Val]]:
    total = 1
    for _, vals in spaces:
        total *= max(1, len(vals))
    if total > ENUM_CAP:
        raise EvalError(f"enumeration space {total} exceeds cap {ENUM_CAP}")
    keys = [k for k, _ in spaces]
    for combo in itertools.product(*[vals for _, vals in spaces]):
        yield dict(zip(keys, combo))
