"""S3 -- Z3 lowering semantics for a canonical SolverQuery.

NON-PRODUCTION SPECIFICATION MATERIAL.

Run under the isolated spec venv:

    .specvenv-z3/Scripts/python.exe spec/reference-semantics/z3_backend.py <query.bin>

Reads canonical SolverQuery octets, lowers them to a Z3 formula, and prints
SAT/UNSAT plus a model.  It shares the DECODER with S2 -- that is deliberate,
since both semantics must agree about what the frozen octets mean -- but the
lowering and the decision procedure are entirely independent of S2's enumerator.

Sort mapping:  Bool -> Bool | Int -> Int | Scaled -> Int on minor units
               Enum -> Int index into the declared member order
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import z3  # noqa: E402

from muster_spec.nodes import Atom, Bool, Int, Node, Rec, Seq, Tagged, decode, encode  # noqa: E402


class LowerError(Exception):
    pass


def var_name(side: str, ref: Node) -> str:
    assert isinstance(ref, Rec)
    pid = ref.fields[0]
    args = ref.fields[1]
    assert isinstance(pid, Atom) and isinstance(args, Seq)
    joined = ",".join(a.value for a in args.items)  # type: ignore[union-attr]
    return f"{side}#{pid.value}({joined})"


def enum_members(domain: Node) -> list[str]:
    assert isinstance(domain, Tagged) and domain.variant == "EnumDomain"
    assert isinstance(domain.value, Rec)
    members = domain.value.fields[0]
    assert isinstance(members, Seq)
    return [m.value for m in members.items]  # type: ignore[union-attr]


class Lowering:
    def __init__(self) -> None:
        self.vars: dict[tuple[str, bytes], object] = {}
        self.kinds: dict[tuple[str, bytes], str] = {}
        self.enum_order: dict[str, list[str]] = {}
        self.decl_domain: dict[tuple[str, bytes], Node] = {}

    # -- declarations ----------------------------------------------------

    def declare(self, side: str, ref: Node, sort: Node, domain: Node) -> None:
        key = (side, encode(ref))
        assert isinstance(sort, Tagged)
        name = var_name(side, ref)
        if sort.variant == "Bool":
            self.vars[key] = z3.Bool(name)
            self.kinds[key] = "bool"
        elif sort.variant == "Int":
            self.vars[key] = z3.Int(name)
            self.kinds[key] = "int"
        elif sort.variant == "Scaled":
            self.vars[key] = z3.Int(name)
            self.kinds[key] = "scaled"
        elif sort.variant == "Enum":
            assert isinstance(sort.value, Rec)
            enum_id = sort.value.fields[0]
            assert isinstance(enum_id, Atom)
            self.enum_order.setdefault(enum_id.value, enum_members(domain))
            self.vars[key] = z3.Int(name)
            self.kinds[key] = "enum"
        else:
            raise LowerError(f"unknown sort {sort.variant}")
        self.decl_domain[key] = domain

    # -- terms -----------------------------------------------------------

    def lower(self, term: Node):  # noqa: ANN201 - z3 expressions are untyped
        if not isinstance(term, Tagged):
            raise LowerError("QTerm must be TAGGED")
        v = term.variant
        L = self.lower

        if v == "Var":
            raise LowerError(
                "unqualified Var in a SolverQuery: every leaf must be world-qualified"
            )
        if v == "QVar":
            qv = term.value
            assert isinstance(qv, Rec) and qv.tag == "QueryVar/v1"
            side, ref = qv.fields
            assert isinstance(side, Atom)
            key = (side.value, encode(ref))
            if key not in self.vars:
                raise LowerError(f"undeclared query variable {key!r}")
            return self.vars[key]
        if v == "LitBool":
            assert isinstance(term.value, Bool)
            return z3.BoolVal(term.value.value)
        if v == "LitInt":
            assert isinstance(term.value, Int)
            return z3.IntVal(term.value.value)
        if v == "LitScaled":
            assert isinstance(term.value, Rec)
            return z3.IntVal(term.value.fields[2].value)  # type: ignore[union-attr]
        if v == "LitEnum":
            assert isinstance(term.value, Rec)
            eid = term.value.fields[0]
            member = term.value.fields[1]
            assert isinstance(eid, Atom) and isinstance(member, Atom)
            order = self.enum_order.get(eid.value)
            if order is None or member.value not in order:
                raise LowerError(f"enum member {member.value!r} not in declared order")
            return z3.IntVal(order.index(member.value))
        if v == "Not":
            return z3.Not(L(term.value))
        if v == "Neg":
            return -L(term.value)
        if v in ("And", "Or", "Add"):
            assert isinstance(term.value, Seq)
            parts = [L(x) for x in term.value.items]
            if v == "And":
                return z3.And(*parts)
            if v == "Or":
                return z3.Or(*parts)
            acc = parts[0]
            for p in parts[1:]:
                acc = acc + p
            return acc
        if v in ("Implies", "Iff", "Sub", "Eq", "Ne", "Lt", "Le", "Gt", "Ge"):
            assert isinstance(term.value, Rec)
            a, b = (L(x) for x in term.value.fields)
            return {
                "Implies": lambda: z3.Implies(a, b),
                "Iff": lambda: a == b,
                "Sub": lambda: a - b,
                "Eq": lambda: a == b,
                "Ne": lambda: a != b,
                "Lt": lambda: a < b,
                "Le": lambda: a <= b,
                "Gt": lambda: a > b,
                "Ge": lambda: a >= b,
            }[v]()
        if v == "MulConst":
            assert isinstance(term.value, Rec)
            k, a = term.value.fields
            assert isinstance(k, Int)
            return z3.IntVal(k.value) * L(a)
        if v == "Ite":
            assert isinstance(term.value, Rec)
            c, t, f = term.value.fields
            return z3.If(L(c), L(t), L(f))
        if v == "EnumTable":
            assert isinstance(term.value, Rec)
            scrut, arms = term.value.fields
            assert isinstance(arms, Seq)
            s = L(scrut)
            items = list(arms.items)
            acc = None
            for arm in reversed(items):
                assert isinstance(arm, Rec)
                m, t = arm.fields
                assert isinstance(m, Atom)
                idx = None
                for order in self.enum_order.values():
                    if m.value in order:
                        idx = order.index(m.value)
                        break
                if idx is None:
                    raise LowerError(f"unknown enum member {m.value!r}")
                acc = L(t) if acc is None else z3.If(s == z3.IntVal(idx), L(t), acc)
            if acc is None:
                raise LowerError("EnumTable requires at least one arm")
            return acc
        raise LowerError(f"unknown QTerm variant {v!r}")


def solve(raw: bytes) -> dict:
    query = decode(raw)
    assert isinstance(query, Rec) and query.tag == "SolverQuery/v1"
    kind = query.fields[0]
    enums = query.fields[2]
    decls = query.fields[3]
    assertions = query.fields[4]
    assert isinstance(kind, Atom) and isinstance(decls, Seq) and isinstance(assertions, Seq)
    assert isinstance(enums, Seq)

    lowering = Lowering()
    for e in enums.items:
        assert isinstance(e, Rec) and e.tag == "EnumDeclaration/v1"
        eid, members = e.fields
        assert isinstance(eid, Atom) and isinstance(members, Seq)
        lowering.enum_order[eid.value] = [m.value for m in members.items]  # type: ignore[union-attr]
    for d in decls.items:
        assert isinstance(d, Rec)
        side, ref, sort, domain = d.fields
        assert isinstance(side, Atom)
        lowering.declare(side.value, ref, sort, domain)

    solver = z3.Solver()
    labels = []
    for a in assertions.items:
        assert isinstance(a, Rec)
        lbl, formula = a.fields
        assert isinstance(lbl, Atom)
        labels.append(lbl.value)
        solver.add(lowering.lower(formula))

    result = solver.check()
    out: dict = {"kind": kind.value, "labels": labels, "result": str(result)}
    if result == z3.sat:
        model = solver.model()
        out["model"] = {str(d): str(model[d]) for d in model.decls()}
    return out


def main() -> int:
    raw = Path(sys.argv[1]).read_bytes()
    print(json.dumps(solve(raw), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
