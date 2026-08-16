"""Self-composition: query construction and the three agreeing semantics.

NON-PRODUCTION SPECIFICATION MATERIAL.

    Sufficient(S)  <=>  UNSAT[ C(w_L) & C(w_R) & (w_L|S = w_R|S)
                              & proj(A(w_L)) != proj(A(w_R)) ]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Hashable, Sequence

from .digests import digest_node
from .hinge import (
    ENUM_CAP,
    EvalError,
    Q,
    T,
    Val,
    domain_values,
    env_world,
    evaluate,
    filler_for,
    lower,
    product,
    qterm_leaf_key,
    term_leaf_key,
    val_to_node,
)
from .nodes import Atom, Bytes, Digest, Int, Node, Rec, Seq, SetV, Tagged, Unit, decode, encode


@dataclass(frozen=True, slots=True)
class VarSpec:
    ref: Node
    sort: Node
    domain: Node

    @property
    def key(self) -> bytes:
        return encode(self.ref)


@dataclass(slots=True)
class Case:
    """A minimal logical case: enough to compute invariance and sufficiency."""

    universe: list[VarSpec]  # unresolved
    known: list[tuple[VarSpec, Val]]  # established facts
    constraints: list[tuple[str, Node]]  # (label, Term)
    program: Node  # DecisionProgram
    action_schema: Node  # ActionSchema
    action_schema_digest: Digest

    @property
    def known_keys(self) -> frozenset[bytes]:
        return frozenset(v.key for v, _ in self.known)

    def var(self, predicate_id: str) -> VarSpec:
        for spec in list(self.universe) + [v for v, _ in self.known]:
            head = spec.ref.fields[0]  # type: ignore[union-attr]
            if isinstance(head, Atom) and head.value == predicate_id:
                return spec
        raise KeyError(predicate_id)


def symbol(predicate_id: str, *args: str) -> Rec:
    return Rec("SymbolRef/v1", [Atom(predicate_id), Seq([Atom(a) for a in args])])


def path_key(ref: Node) -> str:
    return digest_node("SYMBOL_REF", ref).hex()


# --------------------------------------------------------------------------
# action schema helpers
# --------------------------------------------------------------------------


def schema_kinds(action_schema: Node) -> list[tuple[str, list[tuple[str, Node, Node, str]]]]:
    """-> [(kind, [(field_name, sort, bounds, consequentiality)])] in declaration order."""
    assert isinstance(action_schema, Rec)
    kinds = action_schema.fields[2]
    assert isinstance(kinds, Seq)
    out = []
    for ks in kinds.items:
        assert isinstance(ks, Rec)
        kname = ks.fields[0]
        specs = ks.fields[1]
        assert isinstance(kname, Atom) and isinstance(specs, Seq)
        fields = []
        for fs in specs.items:
            assert isinstance(fs, Rec)
            n, sort, bounds, cons = fs.fields[0], fs.fields[1], fs.fields[2], fs.fields[3]
            assert isinstance(n, Atom) and isinstance(cons, Atom)
            fields.append((n.value, sort, bounds, cons.value))
        out.append((kname.value, fields))
    return out


def consequential_fields(action_schema: Node, kind: str) -> list[tuple[str, Node, Node]]:
    for kname, fields in schema_kinds(action_schema):
        if kname == kind:
            return [(n, s, b) for (n, s, b, c) in fields if c == "CONSEQUENTIAL"]
    raise KeyError(kind)


def all_fields(action_schema: Node, kind: str) -> list[tuple[str, Node, Node, str]]:
    for kname, fields in schema_kinds(action_schema):
        if kname == kind:
            return fields
    raise KeyError(kind)


def program_branches(program: Node) -> tuple[list[tuple[Node, Node]], Node]:
    """-> ([(guard Term, ActionTerm)], otherwise ActionTerm)."""
    assert isinstance(program, Rec)
    rules = program.fields[1]
    assert isinstance(rules, Seq)
    branches = []
    for r in rules.items:
        assert isinstance(r, Rec)
        branches.append((r.fields[0], r.fields[1]))
    return branches, program.fields[2]


def action_term_parts(action_term: Node) -> tuple[str, dict[str, Node]]:
    assert isinstance(action_term, Rec)
    k = action_term.fields[0]
    fs = action_term.fields[1]
    assert isinstance(k, Atom) and isinstance(fs, Seq)
    out: dict[str, Node] = {}
    for ft in fs.items:
        assert isinstance(ft, Rec)
        n = ft.fields[0]
        assert isinstance(n, Atom)
        out[n.value] = ft.fields[1]
    return k.value, out


# --------------------------------------------------------------------------
# S1 -- bounded reference semantics.  No query is ever constructed.
# --------------------------------------------------------------------------


def concrete_action(case: Case, world: dict[Hashable, Val]) -> Rec:
    branches, otherwise = program_branches(case.program)
    chosen = otherwise
    for guard, action_term in branches:
        if evaluate(guard, world, term_leaf_key)[1] is True:
            chosen = action_term
            break
    kind, terms = action_term_parts(chosen)
    fields = []
    for name, sort, bounds, _cons in all_fields(case.action_schema, kind):
        if name in terms:
            val = evaluate(terms[name], world, term_leaf_key)
        else:
            val = filler_for(sort, bounds)
        fields.append(Rec("ActionField/v1", [Atom(name), val_to_node(val)]))
    return Rec("Action/v1", [Atom(kind), Seq(fields)])


def project(case: Case, action: Rec) -> Rec:
    kind = action.fields[0]
    assert isinstance(kind, Atom)
    keep = {n for (n, _s, _b) in consequential_fields(case.action_schema, kind.value)}
    fields = action.fields[1]
    assert isinstance(fields, Seq)
    kept = [f for f in fields.items if isinstance(f, Rec) and f.fields[0].value in keep]  # type: ignore[union-attr]
    return Rec(
        "ConsequentialAction/v1",
        [case.action_schema_digest, kind, Seq(kept)],
    )


def feasible_worlds(case: Case) -> list[dict[Hashable, Val]]:
    spaces: list[tuple[Hashable, list[Val]]] = [
        (spec.key, domain_values(spec.sort, spec.domain)) for spec in case.universe
    ]
    base = {spec.key: val for spec, val in case.known}
    out = []
    for assignment in product(spaces):
        world = dict(base)
        world.update(assignment)
        if all(
            evaluate(formula, world, term_leaf_key)[1] is True
            for _label, formula in case.constraints
        ):
            out.append(world)
    return out


def reference_sufficient(case: Case, fixed: Sequence[VarSpec]) -> tuple[bool, tuple | None]:
    """S1: enumerate feasible world pairs agreeing on `fixed`."""
    keys = [f.key for f in fixed]
    worlds = feasible_worlds(case)
    buckets: dict[tuple, list[dict[Hashable, Val]]] = {}
    for w in worlds:
        buckets.setdefault(tuple(w[k] for k in keys), []).append(w)
    for _sig, group in buckets.items():
        seen: dict[bytes, dict[Hashable, Val]] = {}
        for w in group:
            proj = encode(project(case, concrete_action(case, w)))
            if seen and proj not in seen:
                other = next(iter(seen.values()))
                return False, (other, w)
            seen[proj] = w
    return True, None


def reference_invariant(case: Case) -> tuple[str, object]:
    worlds = feasible_worlds(case)
    if not worlds:
        return "Infeasible", None
    projections = {encode(project(case, concrete_action(case, w))): w for w in worlds}
    if len(projections) == 1:
        raw, witness = next(iter(projections.items()))
        return "Invariant", (decode(raw), witness)
    return "Divergent", tuple(list(projections.values())[:2])


# --------------------------------------------------------------------------
# symbolic action lowering  (used by the query, not by S1)
# --------------------------------------------------------------------------


def _kind_index(case: Case, kind: str) -> int:
    for i, (kname, _f) in enumerate(schema_kinds(case.action_schema)):
        if kname == kind:
            return i
    raise KeyError(kind)


def symbolic_kind(case: Case, env) -> Node:
    branches, otherwise = program_branches(case.program)
    okind, _ = action_term_parts(otherwise)
    acc = Q.lit(("int", _kind_index(case, okind)))
    for guard, action_term in reversed(branches):
        kname, _ = action_term_parts(action_term)
        acc = Q.ite(lower(guard, env), Q.lit(("int", _kind_index(case, kname))), acc)
    return acc


def symbolic_field(case: Case, fname: str, sort: Node, bounds: Node, env) -> Node:
    branches, otherwise = program_branches(case.program)

    def branch_value(action_term: Node) -> Node:
        _k, terms = action_term_parts(action_term)
        if fname in terms:
            return lower(terms[fname], env)
        # B2: unreachable on this branch -- the guard below pins the kind.
        return Q.lit(filler_for(sort, bounds))

    acc = branch_value(otherwise)
    for guard, action_term in reversed(branches):
        acc = Q.ite(lower(guard, env), branch_value(action_term), acc)
    return acc


def symbolic_differs(case: Case, env_l, env_r) -> Node:
    """[A1] proj(A(w_L)) != proj(A(w_R)), expressed entirely in canonical QTerm."""
    kl, kr = symbolic_kind(case, env_l), symbolic_kind(case, env_r)
    disjuncts = [Q.ne(kl, kr)]
    for kname, _fields in schema_kinds(case.action_schema):
        conseq = consequential_fields(case.action_schema, kname)
        if not conseq:
            continue
        idx = Q.lit(("int", _kind_index(case, kname)))
        field_diffs = [
            Q.ne(
                symbolic_field(case, fname, sort, bounds, env_l),
                symbolic_field(case, fname, sort, bounds, env_r),
            )
            for (fname, sort, bounds) in conseq
        ]
        disjuncts.append(Q.and_(Q.eq(kl, idx), Q.eq(kr, idx), Q.or_(*field_diffs)))
    return Q.or_(*disjuncts)


# --------------------------------------------------------------------------
# canonical query construction
# --------------------------------------------------------------------------


def _domain_assertion(side: str, spec: VarSpec) -> Node | None:
    dom = spec.domain
    assert isinstance(dom, Tagged)
    leaf = Q.var(spec.ref, side)
    if dom.variant == "BoolDomain":
        return None  # the Bool sort is already total
    if dom.variant in ("IntRange", "ScaledRange"):
        assert isinstance(dom.value, Rec)
        lo, hi = dom.value.fields
        assert isinstance(lo, Int) and isinstance(hi, Int)
        if dom.variant == "IntRange":
            lo_v, hi_v = ("int", lo.value), ("int", hi.value)
        else:
            assert isinstance(spec.sort.value, Rec)  # type: ignore[union-attr]
            unit = spec.sort.value.fields[0].value  # type: ignore[union-attr]
            scale = spec.sort.value.fields[1].value  # type: ignore[union-attr]
            lo_v, hi_v = ("scaled", unit, scale, lo.value), ("scaled", unit, scale, hi.value)
        return Q.and_(Q.ge(leaf, Q.lit(lo_v)), Q.le(leaf, Q.lit(hi_v)))
    if dom.variant == "EnumDomain":
        members = domain_values(spec.sort, spec.domain)
        return Q.or_(*[Q.eq(leaf, Q.lit(m)) for m in members])
    raise EvalError(f"unknown domain {dom.variant}")


def build_sufficiency_query(
    case: Case, fixed: Sequence[VarSpec], logical_case_digest: Digest
) -> Rec:
    known = case.known_keys
    for f in fixed:
        if f.key in known:
            raise EvalError("FixedVariableNotUnresolved: S must be a subset of U (NB-B)")
        if f.key not in {u.key for u in case.universe}:
            raise EvalError("FixedVariableNotUnresolved: S must be a subset of U (NB-B)")

    env_l = env_world("L", known)
    env_r = env_world("R", known)

    decls: list[Node] = []
    assertions: list[tuple[str, Node]] = []

    for spec, val in case.known:
        decls.append(Rec("QueryDecl/v1", [Atom("S"), spec.ref, spec.sort, spec.domain]))
        assertions.append(
            (f"K:{path_key(spec.ref)}", Q.eq(Q.var(spec.ref, "S"), Q.lit(val)))
        )
        dom = _domain_assertion("S", spec)
        if dom is not None:
            assertions.append((f"DOM:S:{path_key(spec.ref)}", dom))

    for spec in case.universe:
        for side in ("L", "R"):
            decls.append(Rec("QueryDecl/v1", [Atom(side), spec.ref, spec.sort, spec.domain]))
            dom = _domain_assertion(side, spec)
            if dom is not None:
                assertions.append((f"DOM:{side}:{path_key(spec.ref)}", dom))

    for label, formula in case.constraints:
        assertions.append((f"C:{label}:L", lower(formula, env_l)))
        assertions.append((f"C:{label}:R", lower(formula, env_r)))

    for spec in fixed:
        assertions.append(
            (
                f"FIX:{path_key(spec.ref)}",
                Q.eq(Q.var(spec.ref, "L"), Q.var(spec.ref, "R")),
            )
        )

    assertions.append(("DIFF", symbolic_differs(case, env_l, env_r)))

    formulas = [Rec("LabeledAssertion/v1", [Atom(lbl), f]) for lbl, f in assertions]
    enums = collect_enums(case, formulas)

    return Rec(
        "SolverQuery/v1",
        [
            Atom("SUFFICIENCY"),
            logical_case_digest,
            Seq(enums),
            Seq(decls),
            Seq(formulas),
        ],
    )


def enum_ids_in(node: Node, into: set[str]) -> None:
    """Every enum a formula mentions, whether through a variable or a literal."""
    if isinstance(node, Tagged):
        if node.variant in ("LitEnum", "VEnum") and isinstance(node.value, Rec):
            head = node.value.fields[0]
            if isinstance(head, Atom):
                into.add(head.value)
        if node.variant == "Enum" and isinstance(node.value, Rec):
            head = node.value.fields[0]
            if isinstance(head, Atom):
                into.add(head.value)
        enum_ids_in(node.value, into)
    elif isinstance(node, Rec):
        for f in node.fields:
            enum_ids_in(f, into)
    elif isinstance(node, (Seq, SetV)):
        for i in node.items:
            enum_ids_in(i, into)


def collect_enums(case: Case, formulas: Sequence[Node]) -> list[Rec]:
    """[A1] Bind the declared member order of every enum the query mentions.

    Without this an enum literal has no canonical index: a backend cannot lower
    `LitEnum(party_id, SUP-12)` deterministically, and two conforming backends
    could disagree about what identical octets denote.
    """
    wanted: set[str] = set()
    for f in formulas:
        enum_ids_in(f, wanted)
    for spec in list(case.universe) + [v for v, _ in case.known]:
        enum_ids_in(spec.sort, wanted)

    order: dict[str, list[str]] = {}

    def note(sort: Node, domain: Node) -> None:
        if (
            isinstance(sort, Tagged)
            and sort.variant == "Enum"
            and isinstance(sort.value, Rec)
            and isinstance(domain, Tagged)
            and domain.variant == "EnumDomain"
            and isinstance(domain.value, Rec)
        ):
            eid = sort.value.fields[0]
            members = domain.value.fields[0]
            if isinstance(eid, Atom) and isinstance(members, Seq):
                order.setdefault(eid.value, [m.value for m in members.items])  # type: ignore[union-attr]

    for spec in list(case.universe) + [v for v, _ in case.known]:
        note(spec.sort, spec.domain)
    for _kind, fields in schema_kinds(case.action_schema):
        for _name, sort, bounds, _cons in fields:
            note(sort, bounds)

    missing = sorted(wanted - set(order))
    if missing:
        raise EvalError(f"UndeclaredEnumOrder: {missing}")

    return [
        Rec("EnumDeclaration/v1", [Atom(eid), Seq([Atom(m) for m in order[eid]])])
        for eid in sorted(wanted)
    ]


# --------------------------------------------------------------------------
# S2 -- canonical query semantics.  Reads octets; knows nothing about worlds.
# --------------------------------------------------------------------------


def evaluate_query_bytes(raw: bytes) -> tuple[bool, dict | None]:
    """Decode canonical SolverQuery octets and decide satisfiability by enumeration.

    Every (side, ref) declaration is an INDEPENDENT variable.  Nothing here knows
    that "L" and "R" are related, so a representation that collapsed the two
    worlds -- or that failed to tie them together where it should -- shows up as a
    disagreement with S1 rather than as a silently plausible answer.
    """
    query = decode(raw)
    assert isinstance(query, Rec) and query.tag == "SolverQuery/v1"
    decls = query.fields[3]
    assertions = query.fields[4]
    assert isinstance(decls, Seq) and isinstance(assertions, Seq)

    spaces: list[tuple[Hashable, list[Val]]] = []
    for d in decls.items:
        assert isinstance(d, Rec)
        side, ref, sort, domain = d.fields
        assert isinstance(side, Atom)
        spaces.append(((side.value, encode(ref)), domain_values(sort, domain)))

    formulas = []
    for a in assertions.items:
        assert isinstance(a, Rec)
        lbl, formula = a.fields
        assert isinstance(lbl, Atom)
        formulas.append((lbl.value, formula))

    for assignment in product(spaces):
        if all(
            evaluate(f, assignment, qterm_leaf_key)[1] is True for _lbl, f in formulas
        ):
            return True, assignment
    return False, None


def canonical_sufficient(
    case: Case, fixed: Sequence[VarSpec], logical_case_digest: Digest
) -> tuple[bool, dict | None]:
    query = build_sufficiency_query(case, fixed, logical_case_digest)
    sat, model = evaluate_query_bytes(encode(query))
    return (not sat), model
