"""Concrete Phase-1 specimens.  Every golden vector is generated from these.

NON-PRODUCTION SPECIFICATION MATERIAL.

All secrets, nonces and salts are FIXED TEST CONSTANTS so the generated vectors
are reproducible.  They are not secrets and must never appear in production.
"""

from __future__ import annotations

from .digests import commitment, digest_node
from .hinge import Q, T, v_enum, v_int, v_scaled
from .nodes import Atom, Bool, Bytes, Digest, Int, Node, Rec, Seq, SetV, Tagged, Unit, encode, none, some
from .selfcomp import Case, VarSpec, symbol
from .signing import Keyring, sign_record
from .registry import REG

# --------------------------------------------------------------------------
# fixed test material
# --------------------------------------------------------------------------

TENANT = "ALPHA"
CASE_ID = "PO-4471"
SALT_CASE = bytes(range(32))
NONCE = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

KEYRING = Keyring(
    {
        "key-gr-1": b"spec-secret-goods-receipt",
        "key-rat-1": b"spec-secret-ratifier",
        "key-case-1": b"spec-secret-case-builder",
        "key-muster-1": b"spec-secret-muster-envelope",
        "key-hr-1": b"spec-secret-hr",
    }
)

T_2026_01_01 = 1_767_225_600_000_000  # 2026-01-01T00:00:00Z in microseconds
T_2026_06_01 = 1_780_272_000_000_000
AS_OF = 1_781_000_000_000_000


def instant(v: int) -> Int:
    return Int(v)


def interval(start: int, end: int | None = None) -> Rec:
    return Rec("HalfOpen/v1", [Int(start), none() if end is None else some(Int(end))])


# --------------------------------------------------------------------------
# sorts and domains
# --------------------------------------------------------------------------

SORT_BOOL = Tagged("Bool", Unit())
SORT_INT = Tagged("Int", Unit())
SORT_INR = Tagged("Scaled", Rec("ScaledSort/v1", [Atom("INR"), Int(2)]))
SORT_PARTY = Tagged("Enum", Rec("EnumSort/v1", [Atom("party_id")]))
SORT_BASIS = Tagged("Enum", Rec("EnumSort/v1", [Atom("basis")]))
SORT_REASON = Tagged("Enum", Rec("EnumSort/v1", [Atom("reason")]))

DOM_BOOL = Tagged("BoolDomain", Unit())


def dom_int(lo: int, hi: int) -> Tagged:
    return Tagged("IntRange", Rec("IntRange/v1", [Int(lo), Int(hi)]))


def dom_scaled(lo: int, hi: int) -> Tagged:
    return Tagged("ScaledRange", Rec("ScaledRange/v1", [Int(lo), Int(hi)]))


def dom_enum(*members: str) -> Tagged:
    return Tagged("EnumDomain", Rec("EnumDomain/v1", [Seq([Atom(m) for m in members])]))


DOM_PARTY = dom_enum("SUP-12", "SUP-99")
DOM_BASIS = dom_enum("FIXED", "PRORATA")
DOM_REASON = dom_enum("DISPUTED_QUANTITY", "MISSING_RECEIPT")


# --------------------------------------------------------------------------
# A1 -- the mandatory counterexample: q in {0,1}, action = PAY(q)
# --------------------------------------------------------------------------

A1_Q = symbol("q")

A1_ACTION_SCHEMA = Rec(
    "ActionSchema/v1",
    [
        Atom("a1-minimal"),
        Int(1),
        Seq(
            [
                Rec(
                    "ActionKindSpec/v1",
                    [
                        Atom("PAY"),
                        Seq(
                            [
                                Rec(
                                    "FieldSpec/v1",
                                    [
                                        Atom("amount"),
                                        SORT_INT,
                                        dom_int(0, 1),
                                        Atom("CONSEQUENTIAL"),
                                        Bool(True),
                                        none(),
                                    ],
                                )
                            ]
                        ),
                    ],
                )
            ]
        ),
    ],
)

A1_PROGRAM = Rec(
    "DecisionProgram/v1",
    [
        Seq([A1_Q]),
        Seq([]),  # no guarded rules: the action is the otherwise branch
        Rec(
            "ActionTerm/v1",
            [Atom("PAY"), Seq([Rec("FieldTerm/v1", [Atom("amount"), T.var(A1_Q)])])],
        ),
    ],
)


def a1_case() -> Case:
    return Case(
        universe=[VarSpec(A1_Q, SORT_INT, dom_int(0, 1))],
        known=[],
        constraints=[],
        program=A1_PROGRAM,
        action_schema=A1_ACTION_SCHEMA,
        action_schema_digest=digest_node("ACTION_SCHEMA", A1_ACTION_SCHEMA),
    )


# --------------------------------------------------------------------------
# A1-correlated -- a second world-qualification probe with a dependent variable
# --------------------------------------------------------------------------

CORR_X = symbol("x")
CORR_Y = symbol("y")

CORR_SCHEMA = A1_ACTION_SCHEMA  # same shape, amount in {0,1}

CORR_PROGRAM = Rec(
    "DecisionProgram/v1",
    [
        Seq([CORR_X, CORR_Y]),
        Seq([]),
        Rec(
            "ActionTerm/v1",
            [Atom("PAY"), Seq([Rec("FieldTerm/v1", [Atom("amount"), T.var(CORR_Y)])])],
        ),
    ],
)


def correlated_case() -> Case:
    """y is pinned to x by a constraint, so fixing x alone is already sufficient."""
    return Case(
        universe=[
            VarSpec(CORR_X, SORT_INT, dom_int(0, 1)),
            VarSpec(CORR_Y, SORT_INT, dom_int(0, 1)),
        ],
        known=[],
        constraints=[("C-CORR", T.eq(T.var(CORR_Y), T.var(CORR_X)))],
        program=CORR_PROGRAM,
        action_schema=CORR_SCHEMA,
        action_schema_digest=digest_node("ACTION_SCHEMA", CORR_SCHEMA),
    )


# --------------------------------------------------------------------------
# procurement -- the running worked example
# --------------------------------------------------------------------------

Q_REF = symbol("accepted_quantity", "PO-4471")

PREDICATE_SCHEMA = Rec(
    "PredicateSchema/v1",
    [
        Int(1),
        Seq(
            [
                Rec(
                    "PredicateSpec/v1",
                    [
                        Atom("accepted_quantity"),
                        Seq([Atom("purchase_order")]),
                        SORT_INT,
                        dom_int(0, 120),
                        Atom("OBSERVATION"),
                        Atom("ATTESTABLE"),
                        SetV([Atom("GOODS_RECEIPT_SYSTEM")]),
                        some(Atom("COUNT")),
                    ],
                )
            ]
        ),
    ],
)

ACTION_SCHEMA = Rec(
    "ActionSchema/v1",
    [
        Atom("procurement-demo"),
        Int(1),
        Seq(
            [
                Rec(
                    "ActionKindSpec/v1",
                    [
                        Atom("PAY"),
                        Seq(
                            [
                                Rec(
                                    "FieldSpec/v1",
                                    [
                                        Atom("recipient"),
                                        SORT_PARTY,
                                        DOM_PARTY,
                                        Atom("CONSEQUENTIAL"),
                                        Bool(True),
                                        none(),
                                    ],
                                ),
                                Rec(
                                    "FieldSpec/v1",
                                    [
                                        Atom("amount"),
                                        SORT_INR,
                                        dom_scaled(0, 100_000_00),
                                        Atom("CONSEQUENTIAL"),
                                        Bool(True),
                                        none(),
                                    ],
                                ),
                                Rec(
                                    "FieldSpec/v1",
                                    [
                                        Atom("basis_code"),
                                        SORT_BASIS,
                                        DOM_BASIS,
                                        Atom("DIAGNOSTIC"),
                                        Bool(False),
                                        some(Tagged("VEnum", Rec("VEnum/v1", [Atom("basis"), Atom("FIXED")]))),
                                    ],
                                ),
                            ]
                        ),
                    ],
                ),
                Rec(
                    "ActionKindSpec/v1",
                    [
                        Atom("HOLD_FOR_REVIEW"),
                        Seq(
                            [
                                Rec(
                                    "FieldSpec/v1",
                                    [
                                        Atom("reason_code"),
                                        SORT_REASON,
                                        DOM_REASON,
                                        Atom("DIAGNOSTIC"),
                                        Bool(False),
                                        some(
                                            Tagged(
                                                "VEnum",
                                                Rec("VEnum/v1", [Atom("reason"), Atom("DISPUTED_QUANTITY")]),
                                            )
                                        ),
                                    ],
                                )
                            ]
                        ),
                    ],
                ),
            ]
        ),
    ],
)

ACTION_SCHEMA_DIGEST = digest_node("ACTION_SCHEMA", ACTION_SCHEMA)
PREDICATE_SCHEMA_DIGEST = digest_node("PREDICATE_SCHEMA", PREDICATE_SCHEMA)


def _pay(amount_minor: int, basis: str) -> Rec:
    return Rec(
        "ActionTerm/v1",
        [
            Atom("PAY"),
            Seq(
                [
                    Rec("FieldTerm/v1", [Atom("recipient"), T.lit(v_enum("party_id", "SUP-12"))]),
                    Rec("FieldTerm/v1", [Atom("amount"), T.lit(v_scaled("INR", 2, amount_minor))]),
                    Rec("FieldTerm/v1", [Atom("basis_code"), T.lit(v_enum("basis", basis))]),
                ]
            ),
        ],
    )


DECISION_PROGRAM = Rec(
    "DecisionProgram/v1",
    [
        Seq([Q_REF]),
        Seq(
            [
                Rec(
                    "ProgramRule/v1",
                    [T.ge(T.var(Q_REF), T.lit(v_int(100))), _pay(6_300_000, "FIXED")],
                )
            ]
        ),
        _pay(6_237_000, "PRORATA"),
    ],
)


def procurement_case(lower_bound: int = 99) -> Case:
    """`ClosedLowerBound(accepted_quantity, 99)` attested; nothing else known."""
    return Case(
        universe=[VarSpec(Q_REF, SORT_INT, dom_int(0, 120))],
        known=[],
        constraints=[("C-ATT-1", T.ge(T.var(Q_REF), T.lit(v_int(lower_bound))))],
        program=DECISION_PROGRAM,
        action_schema=ACTION_SCHEMA,
        action_schema_digest=ACTION_SCHEMA_DIGEST,
    )


# --------------------------------------------------------------------------
# HOLD specimens -- diagnostics differ, consequential projection does not
# --------------------------------------------------------------------------


def hold_action(reason: str) -> Rec:
    return Rec(
        "Action/v1",
        [
            Atom("HOLD_FOR_REVIEW"),
            Seq(
                [
                    Rec(
                        "ActionField/v1",
                        [Atom("reason_code"), Tagged("VEnum", Rec("VEnum/v1", [Atom("reason"), Atom(reason)]))],
                    )
                ]
            ),
        ],
    )


PAY_ACTION = Rec(
    "Action/v1",
    [
        Atom("PAY"),
        Seq(
            [
                Rec(
                    "ActionField/v1",
                    [Atom("recipient"), Tagged("VEnum", Rec("VEnum/v1", [Atom("party_id"), Atom("SUP-12")]))],
                ),
                Rec(
                    "ActionField/v1",
                    [Atom("amount"), Tagged("VScaled", Rec("VScaled/v1", [Atom("INR"), Int(2), Int(6_300_000)]))],
                ),
                Rec(
                    "ActionField/v1",
                    [Atom("basis_code"), Tagged("VEnum", Rec("VEnum/v1", [Atom("basis"), Atom("FIXED")]))],
                ),
            ]
        ),
    ],
)

PAY_CONSEQUENTIAL = Rec(
    "ConsequentialAction/v1",
    [
        ACTION_SCHEMA_DIGEST,
        Atom("PAY"),
        Seq(list(PAY_ACTION.fields[1].items)[:2]),  # type: ignore[union-attr]
    ],
)
