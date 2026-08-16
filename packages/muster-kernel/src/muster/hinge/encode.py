"""Building the canonical solver query.

Every assertion carries a label a reader can recompute from the case:
``K:<key>``, ``DOM:<side>:<key>``, ``C:<label>:<side>``, ``FIX:<key>``, ``DIFF``.
Source-derived labels are exactly the ``C:`` ones; the rest are internal
encoding assertions and are query-scoped, which is why an unsatisfiable core is
reported as *contributing source constraints* and never as the whole core.

Lowering is a leaf rewrite, so the two worlds share what is already established
by construction:

    env_L(v) = SINGLE if v is established else LEFT
    env_R(v) = SINGLE if v is established else RIGHT

The action comparison is expressed entirely in the query grammar.  The kind of
an action is an enum term over the program's branches; a consequential field is
an enum-guarded selector over the same branches.  Filler values appear only on
branches a kind guard excludes, so they are never read -- structurally, not by
argument.
"""

from __future__ import annotations

from collections.abc import Callable

from muster.core.actions import ConsequentialAction
from muster.core.expr.domains import domain_formula
from muster.core.expr.ir import (
    Binary,
    BinaryOp,
    Ite,
    Leaf,
    LitEnum,
    NAry,
    NAryOp,
    map_leaves,
)
from muster.core.expr.terms import Term, literal
from muster.core.results import InvariantViolation
from muster.core.values.scalars import VEnum
from muster.core.values.sorts import Domain, EnumDomain, EnumSort, Sort
from muster.core.values.symbols import SymbolRef
from muster.core.wire.codec import encode
from muster.hinge.project import ProjectedCase
from muster.policy.program import ActionTerm, field_spec
from muster.solve.query import (
    EnumDeclaration,
    LabeledAssertion,
    QTerm,
    QueryDecl,
    QueryKind,
    QueryVar,
    SolverQuery,
    WorldSide,
)

type Env = Callable[[SymbolRef], WorldSide]

LABEL_DIFF = "DIFF"
LABEL_PREFIX_SOURCE = "C:"


def single_world_env(_: SymbolRef) -> WorldSide:
    return WorldSide.SINGLE


def feasibility_query(case: ProjectedCase) -> SolverQuery:
    """``SAT[ C(w) ]`` -- and the model is the witness an invariant outcome needs."""
    return _one_world_query(case, QueryKind.FEASIBILITY, ())


def invariance_query(case: ProjectedCase, witness: ConsequentialAction) -> SolverQuery:
    """``UNSAT[ C(w) and A(w) != A(w0) ]`` against an established witness."""
    return _one_world_query(case, QueryKind.INVARIANCE, (witness,))


def blocking_query(case: ProjectedCase, excluded: tuple[ConsequentialAction, ...]) -> SolverQuery:
    """Feasibility restricted to worlds whose action is none of ``excluded``.

    Reachable-action enumeration is a loop over this query, so it uses the same
    machinery as invariance and works against any backend rather than needing an
    enumeration-shaped one.
    """
    return _one_world_query(case, QueryKind.FEASIBILITY, excluded)


def sufficiency_query(case: ProjectedCase, fixed: frozenset[SymbolRef]) -> SolverQuery:
    """``UNSAT[ C(w) and C(w') and w|S = w'|S and A(w) != A(w') ]``."""
    known = set(case.logical.assignment())
    for ref in fixed:
        if ref in known:
            #  Fixing something already established is not a harmless no-op: it
            #  silently answers a different question from the one asked.
            raise InvariantViolation(f"{ref} is established and cannot be fixed")

    def env_left(ref: SymbolRef) -> WorldSide:
        return WorldSide.SINGLE if ref in known else WorldSide.LEFT

    def env_right(ref: SymbolRef) -> WorldSide:
        return WorldSide.SINGLE if ref in known else WorldSide.RIGHT

    declarations = _declarations(case, two_world=True)
    assertions = list(_known_assertions(case))
    assertions.extend(_domain_assertions(case, declarations))
    assertions.extend(_constraint_assertions(case, env_left, WorldSide.LEFT))
    assertions.extend(_constraint_assertions(case, env_right, WorldSide.RIGHT))
    assertions.extend(
        LabeledAssertion(
            f"FIX:{ref.key()}",
            Binary(
                BinaryOp.EQ,
                _leaf(WorldSide.LEFT, ref),
                _leaf(WorldSide.RIGHT, ref),
            ),
        )
        for ref in sorted(fixed, key=lambda item: encode(item.to_node()))
    )
    assertions.append(LabeledAssertion(LABEL_DIFF, _actions_differ(case, env_left, env_right)))
    return SolverQuery(
        QueryKind.SUFFICIENCY,
        case.logical.digest(),
        _enum_declarations(case),
        declarations,
        tuple(assertions),
    )


def _one_world_query(
    case: ProjectedCase, kind: QueryKind, excluded: tuple[ConsequentialAction, ...]
) -> SolverQuery:
    declarations = _declarations(case, two_world=False)
    assertions = list(_known_assertions(case))
    assertions.extend(_domain_assertions(case, declarations))
    assertions.extend(_constraint_assertions(case, single_world_env, WorldSide.SINGLE))
    for action in excluded:
        assertions.append(
            LabeledAssertion(
                LABEL_DIFF if len(excluded) == 1 else f"{LABEL_DIFF}:{action.digest().hex[:16]}",
                _differs_from(case, single_world_env, action),
            )
        )
    return SolverQuery(
        kind,
        case.logical.digest(),
        _enum_declarations(case),
        declarations,
        tuple(assertions),
    )


def _declarations(case: ProjectedCase, *, two_world: bool) -> tuple[QueryDecl, ...]:
    known = set(case.logical.assignment())
    decls: list[QueryDecl] = []
    for declaration in case.declarations:
        sides = (
            (WorldSide.SINGLE,)
            if not two_world or declaration.ref in known
            else (WorldSide.LEFT, WorldSide.RIGHT)
        )
        decls.extend(
            QueryDecl(side, declaration.ref, declaration.sort, declaration.domain) for side in sides
        )
    return tuple(sorted(decls, key=lambda decl: encode(decl.to_node())))


def _known_assertions(case: ProjectedCase) -> list[LabeledAssertion]:
    return sorted(
        (
            LabeledAssertion(
                f"K:{fact.ref.key()}",
                Binary(
                    BinaryOp.EQ,
                    _leaf(WorldSide.SINGLE, fact.ref),
                    literal(fact.value),
                ),
            )
            for fact in case.logical.known
        ),
        key=lambda assertion: assertion.label,
    )


def _domain_assertions(
    case: ProjectedCase, declarations: tuple[QueryDecl, ...]
) -> list[LabeledAssertion]:
    del case
    return [
        LabeledAssertion(
            f"DOM:{decl.side.value}:{decl.ref.key()}",
            _domain_formula(decl.side, decl.ref, decl.sort, decl.domain),
        )
        for decl in declarations
    ]


def _constraint_assertions(
    case: ProjectedCase, env: Env, side: WorldSide
) -> list[LabeledAssertion]:
    return sorted(
        (
            LabeledAssertion(
                f"{LABEL_PREFIX_SOURCE}{constraint.label}:{side.value}",
                _lower(constraint.formula, env),
            )
            for constraint in case.logical.constraints
        ),
        key=lambda assertion: assertion.label,
    )


def _enum_declarations(case: ProjectedCase) -> tuple[EnumDeclaration, ...]:
    """Every enum the query mentions, with its declared member order."""
    declared: dict[str, tuple[str, ...]] = {}
    for declaration in case.declarations:
        if isinstance(declaration.sort, EnumSort) and isinstance(declaration.domain, EnumDomain):
            declared[declaration.sort.enum_id] = declaration.domain.members
    schema = case.action_schema
    existing = declared.get(schema.kind_enum_id())
    if existing is not None and existing != schema.kind_members():
        raise InvariantViolation(
            f"enum id {schema.kind_enum_id()} is declared twice with different members"
        )
    declared[schema.kind_enum_id()] = schema.kind_members()
    return tuple(EnumDeclaration(enum_id, members) for enum_id, members in sorted(declared.items()))


def _leaf(side: WorldSide, ref: SymbolRef) -> QTerm:
    return Leaf(QueryVar(side, ref))


def _lower(term: Term, env: Env) -> QTerm:
    return map_leaves(term, lambda ref: QueryVar(env(ref), ref))


def _domain_formula(side: WorldSide, ref: SymbolRef, sort: Sort, domain: Domain) -> QTerm:
    return domain_formula(_leaf(side, ref), sort, domain)


def _kind_term(case: ProjectedCase, env: Env) -> QTerm:
    enum_id = case.action_schema.kind_enum_id()
    program = case.program
    result: QTerm = LitEnum(VEnum(enum_id, program.otherwise.kind))
    for rule in reversed(program.rules):
        result = Ite(
            _lower(rule.guard, env),
            LitEnum(VEnum(enum_id, rule.action.kind)),
            result,
        )
    return result


def _field_term(case: ProjectedCase, kind: str, field_name: str, env: Env) -> QTerm:
    """A consequential field of the action the program produces, as one term."""
    schema = case.action_schema
    spec = schema.kind_spec(kind)
    if spec is None:  # pragma: no cover - compiled programs name declared kinds
        raise InvariantViolation(f"unknown action kind {kind}")
    declared = field_spec(spec.fields, field_name)
    if declared is None:  # pragma: no cover
        raise InvariantViolation(f"unknown field {kind}.{field_name}")
    filler: QTerm = literal(declared.filler())

    def branch(action: ActionTerm) -> QTerm:
        term = action.field_term(field_name)
        return _lower(term, env) if term is not None else filler

    program = case.program
    result = branch(program.otherwise)
    for rule in reversed(program.rules):
        result = Ite(_lower(rule.guard, env), branch(rule.action), result)
    return result


def _actions_differ(case: ProjectedCase, env_left: Env, env_right: Env) -> QTerm:
    """The two worlds produce different consequential actions."""
    schema = case.action_schema
    enum_id = schema.kind_enum_id()
    kind_left = _kind_term(case, env_left)
    kind_right = _kind_term(case, env_right)

    disjuncts: list[QTerm] = [Binary(BinaryOp.NE, kind_left, kind_right)]
    for spec in schema.kinds:
        fields = spec.consequential()
        if not fields:  # pragma: no cover - schema validation requires at least one
            continue
        differences = tuple(
            Binary(
                BinaryOp.NE,
                _field_term(case, spec.kind, field.name, env_left),
                _field_term(case, spec.kind, field.name, env_right),
            )
            for field in fields
        )
        same_kind = LitEnum(VEnum(enum_id, spec.kind))
        disjuncts.append(
            NAry(
                NAryOp.AND,
                (
                    Binary(BinaryOp.EQ, kind_left, same_kind),
                    Binary(BinaryOp.EQ, kind_right, same_kind),
                    differences[0] if len(differences) == 1 else NAry(NAryOp.OR, differences),
                ),
            )
        )
    return disjuncts[0] if len(disjuncts) == 1 else NAry(NAryOp.OR, tuple(disjuncts))


def _differs_from(case: ProjectedCase, env: Env, action: ConsequentialAction) -> QTerm:
    """This world's action is not the given constant action.

    Equivalent to the two-world form with one side grounded: when the kinds
    differ the first disjunct already holds, so the field comparisons on the
    excluded branches cannot change the answer.
    """
    schema = case.action_schema
    enum_id = schema.kind_enum_id()
    disjuncts: list[QTerm] = [
        Binary(
            BinaryOp.NE,
            _kind_term(case, env),
            LitEnum(VEnum(enum_id, action.kind)),
        )
    ]
    disjuncts.extend(
        Binary(
            BinaryOp.NE,
            _field_term(case, action.kind, field.name, env),
            literal(field.value),
        )
        for field in action.consequential_fields
    )
    return disjuncts[0] if len(disjuncts) == 1 else NAry(NAryOp.OR, tuple(disjuncts))
