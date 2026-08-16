"""[A1] World-qualified self-composition, and the failures it now prevents."""

from __future__ import annotations

import json
import subprocess
import sys
from itertools import combinations
from pathlib import Path

import pytest

from muster_spec import fixtures as F
from muster_spec.digests import digest_node
from muster_spec.hinge import Q, T
from muster_spec.nodes import Atom, Int, Rec, Seq, Tagged, encode
from muster_spec.registry import REG
from muster_spec.schema import Ref, SchemaError, validate
from muster_spec.selfcomp import (
    build_sufficiency_query,
    canonical_sufficient,
    evaluate_query_bytes,
    reference_sufficient,
)

ROOT = Path(__file__).resolve().parents[3]
VENV_PY = ROOT / ".specvenv-z3" / "Scripts" / "python.exe"
BACKEND = Path(__file__).resolve().parents[1] / "z3_backend.py"

LCD = digest_node("LOGICAL_CASE", Atom("a1"))


def z3_available() -> bool:
    return VENV_PY.exists() and BACKEND.exists()


def z3_sufficient(query: Rec, tmp_path: Path) -> bool:
    """S3: lower the canonical octets to Z3.  Sufficient <=> UNSAT."""
    blob = tmp_path / "q.bin"
    blob.write_bytes(encode(query))
    out = subprocess.run(
        [str(VENV_PY), str(BACKEND), str(blob)], capture_output=True, text=True, check=True
    )
    result = json.loads(out.stdout)["result"]
    assert result in ("sat", "unsat"), result
    return result == "unsat"


# --------------------------------------------------------------------------
# the mandatory counterexample
# --------------------------------------------------------------------------


def test_A1_MANDATORY_q_in_0_1_pay_q(tmp_path):
    case = F.a1_case()
    q = case.universe[0]

    s1_fixed, _ = reference_sufficient(case, [q])
    s2_fixed, _ = canonical_sufficient(case, [q], LCD)
    assert s1_fixed is True
    assert s2_fixed is True

    s1_empty, witness_pair = reference_sufficient(case, [])
    s2_empty, model = canonical_sufficient(case, [], LCD)
    assert s1_empty is False
    assert s2_empty is False

    # The witness is exactly q_LEFT = 0, q_RIGHT = 1.
    assert model is not None
    left = model[("L", encode(q.ref))]
    right = model[("R", encode(q.ref))]
    assert {left, right} == {("int", 0), ("int", 1)}

    if z3_available():
        assert z3_sufficient(build_sufficiency_query(case, [q], LCD), tmp_path) is True
        assert z3_sufficient(build_sufficiency_query(case, [], LCD), tmp_path) is False


@pytest.mark.parametrize("builder", [F.a1_case, F.correlated_case, lambda: F.procurement_case(99)])
def test_three_semantics_agree_on_every_subset(builder, tmp_path):
    case = builder()
    universe = case.universe
    for size in range(len(universe) + 1):
        for fixed in combinations(universe, size):
            s1, _ = reference_sufficient(case, list(fixed))
            s2, _ = canonical_sufficient(case, list(fixed), LCD)
            assert s1 == s2, f"S1/S2 disagree for {[f.key for f in fixed]}"
            if z3_available():
                s3 = z3_sufficient(build_sufficiency_query(case, list(fixed), LCD), tmp_path)
                assert s1 == s3, f"S1/S3 disagree for {[f.key for f in fixed]}"


def test_correlated_case_fixing_x_alone_is_sufficient():
    """y is pinned to x, so fixing x determines the action even though y is free."""
    case = F.correlated_case()
    x, y = case.universe
    assert reference_sufficient(case, [x])[0] is True
    assert canonical_sufficient(case, [x], LCD)[0] is True
    assert reference_sufficient(case, [])[0] is False
    assert canonical_sufficient(case, [], LCD)[0] is False


# --------------------------------------------------------------------------
# the failure modes the representation now prevents
# --------------------------------------------------------------------------


def test_omitting_FIX_yields_spurious_insufficiency():
    """The Phase 0.7 representation could not express FIX at all.

    Dropping it from an otherwise identical query flips the verdict, which is why
    an unrepresentable FIX was a soundness defect and not a cosmetic one.
    """
    case = F.a1_case()
    q = case.universe[0]
    full = build_sufficiency_query(case, [q], LCD)
    assertions = full.fields[4].items
    without_fix = Seq([a for a in assertions if not a.fields[0].value.startswith("FIX:")])
    crippled = Rec(
        "SolverQuery/v1",
        [full.fields[0], full.fields[1], full.fields[2], full.fields[3], without_fix],
    )

    assert canonical_sufficient(case, [q], LCD)[0] is True
    sat, _ = evaluate_query_bytes(encode(crippled))
    assert sat is True  # SAT => "not sufficient", the wrong answer


def test_collapsing_the_two_worlds_yields_spurious_invariance():
    """Rewriting every L/R leaf to the shared side makes divergence unsatisfiable."""
    case = F.a1_case()
    q = case.universe[0]
    query = build_sufficiency_query(case, [], LCD)

    def collapse(node):
        if isinstance(node, Rec) and node.tag == "QueryVar/v1":
            return Rec("QueryVar/v1", [Atom("S"), node.fields[1]])
        if isinstance(node, Rec):
            return Rec(node.tag, [collapse(f) for f in node.fields])
        if isinstance(node, Tagged):
            return Tagged(node.variant, collapse(node.value))
        if isinstance(node, Seq):
            return Seq([collapse(i) for i in node.items])
        return node

    decls = Seq([Rec("QueryDecl/v1", [Atom("S"), q.ref, q.sort, q.domain])])
    collapsed = Rec(
        "SolverQuery/v1",
        [query.fields[0], query.fields[1], query.fields[2], decls, collapse(query.fields[4])],
    )
    sat, _ = evaluate_query_bytes(encode(collapsed))
    assert sat is False  # UNSAT => "invariant", the wrong answer
    assert canonical_sufficient(case, [], LCD)[0] is False


def test_bare_Var_in_a_query_assertion_is_rejected_by_the_schema():
    """CHK_QUERY_ASSERTION_CANNOT_CONTAIN_BARE_VAR, enforced structurally."""
    bad = Rec("LabeledAssertion/v1", [Atom("FIX:bogus"), T.var(F.A1_Q)])
    with pytest.raises(SchemaError, match="not a variant of QTerm"):
        validate(REG, bad, Ref("LabeledAssertion"))


def test_QueryVar_in_a_policy_constraint_is_rejected_by_the_schema():
    """The policy IR must not know about worlds."""
    bad = Rec(
        "Constraint/v1",
        [
            Atom("C-BAD"),
            Q.var(F.A1_Q, "L"),
            Tagged("Structural", Rec("StructuralDeriv/v1", [F.PREDICATE_SCHEMA_DIGEST])),
        ],
    )
    with pytest.raises(SchemaError, match="not a variant of Term"):
        validate(REG, bad, Ref("Constraint"))


def test_query_validates_against_the_declared_type():
    case = F.a1_case()
    query = build_sufficiency_query(case, [case.universe[0]], LCD)
    validate(REG, query, Ref("SolverQuery"))


def test_known_values_are_shared_across_both_worlds():
    """A known value is declared once on side S, never duplicated per world."""
    from muster_spec.hinge import v_int
    from muster_spec.selfcomp import Case, VarSpec

    known_spec = VarSpec(F.symbol("k"), F.SORT_INT, F.dom_int(0, 3))
    case = Case(
        universe=[VarSpec(F.A1_Q, F.SORT_INT, F.dom_int(0, 1))],
        known=[(known_spec, v_int(2))],
        constraints=[],
        program=F.A1_PROGRAM,
        action_schema=F.A1_ACTION_SCHEMA,
        action_schema_digest=digest_node("ACTION_SCHEMA", F.A1_ACTION_SCHEMA),
    )
    query = build_sufficiency_query(case, [], LCD)
    sides = {}
    for d in query.fields[3].items:
        sides.setdefault(encode(d.fields[1]), set()).add(d.fields[0].value)
    assert sides[encode(known_spec.ref)] == {"S"}
    assert sides[encode(F.A1_Q)] == {"L", "R"}


def test_S_must_be_a_subset_of_U():
    """NB-B: a member of dom(K) in S is rejected, never silently a no-op."""
    from muster_spec.hinge import EvalError, v_int
    from muster_spec.selfcomp import Case, VarSpec

    known_spec = VarSpec(F.symbol("k"), F.SORT_INT, F.dom_int(0, 3))
    case = Case(
        universe=[VarSpec(F.A1_Q, F.SORT_INT, F.dom_int(0, 1))],
        known=[(known_spec, v_int(2))],
        constraints=[],
        program=F.A1_PROGRAM,
        action_schema=F.A1_ACTION_SCHEMA,
        action_schema_digest=digest_node("ACTION_SCHEMA", F.A1_ACTION_SCHEMA),
    )
    with pytest.raises(EvalError, match="FixedVariableNotUnresolved"):
        build_sufficiency_query(case, [known_spec], LCD)


def test_query_bytes_are_deterministic():
    case = F.a1_case()
    q = case.universe[0]
    a = encode(build_sufficiency_query(case, [q], LCD))
    b = encode(build_sufficiency_query(F.a1_case(), [F.a1_case().universe[0]], LCD))
    assert a == b
