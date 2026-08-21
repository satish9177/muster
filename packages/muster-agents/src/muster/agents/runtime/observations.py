"""What a model may say, and the deterministic gate every word of it passes.

A model does not return a fact.  It returns a **candidate**: a target label, a
relation kind, a value spelled as text, an instant spelled as text, and a
reference to the local material it read.  Nothing else is expressible, because
nothing else is an argument.

Three properties do the work, and each is an absence rather than a check.

**A model cannot name a proposition.**  It names a *label* -- ``T1``, ``T2`` --
drawn from the assignment it was briefed on, and the label resolves to a target
the control plane wrote.  There is no argument through which a predicate
identifier or an argument list could arrive, so "the site agent invented a
proposition" is not a failure mode that needs guarding against; it is
unrepresentable.

**A model cannot widen a value.**  The value is parsed against the *pinned*
sort and checked against the *pinned* domain, both copied from the bundle into
the assignment by the control plane.  A boolean predicate accepts two spellings
and a bounded integer accepts the integers inside its bounds; everything else
is a typed refusal that creates nothing.

**A model cannot express confidence.**  There is no field for one, and that is
deliberate rather than an oversight: a number a model produces about its own
output is not evidence about the world, and any field carrying one becomes a
threshold, and any threshold becomes a truth.  What a model *can* do is decline,
and declining is a first-class outcome that creates nothing.

The spelling of a value is text rather than a typed argument per sort, and the
reason is closure: one tool with one closed argument list serves every sort a
bundle can declare, so adding a domain adds no tool, no branch and no place for
an unvalidated path to appear.  The parser below is the type system, and it is
the only one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from muster.core.evidence.acquisition import AcquisitionAssignment, AcquisitionTargetSpec
from muster.core.evidence.relations import (
    AcquisitionRelation,
    ClosedLowerBound,
    ClosedUpperBound,
    EnumSubset,
    ExactValue,
)
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.core.values.scalars import Value, VBool, VEnum, VInt, VScaled, value_in_domain
from muster.core.values.sorts import (
    BoolSort,
    Domain,
    EnumDomain,
    EnumSort,
    IntSort,
    ScaledSort,
    Sort,
)
from muster.core.values.symbols import SymbolRef
from muster.core.values.times import Instant

#: Microseconds per second, for turning a parsed timestamp into a wire instant.
MICROSECONDS = 1_000_000

#: What a model may name as a relation.  Four spellings, matching the four
#: acquisition relations the wire contract has and adding none: a source says
#: exactly, at least, at most, or one of.
RELATION_EXACT = "exact"
RELATION_AT_LEAST = "at_least"
RELATION_AT_MOST = "at_most"
RELATION_ONE_OF = "one_of"

RELATION_KINDS: tuple[str, ...] = (
    RELATION_EXACT,
    RELATION_AT_LEAST,
    RELATION_AT_MOST,
    RELATION_ONE_OF,
)

_BOOLEAN_SPELLINGS = {"true": True, "false": False}


def label_for(index: int) -> str:
    """The stable label a target is briefed under.  One-based, so ``T1`` is first."""
    return f"T{index + 1}"


def labelled(assignment: AcquisitionAssignment) -> dict[str, AcquisitionTargetSpec]:
    """The assignment's targets, keyed by the label the brief will use."""
    return {label_for(index): target for index, target in enumerate(assignment.targets)}


@dataclass(frozen=True, slots=True)
class CandidateObservation:
    """Exactly what a model said, before anything has been believed about it.

    Every field is a string, and every field is untrusted.  Keeping the raw
    strings rather than parsing at the tool boundary is what lets a rejection
    say *what the model actually produced* -- which is the difference between a
    debuggable model-boundary failure and "the agent returned nothing".
    """

    label: str
    relation: str
    value: str
    observed_at: str
    #: Which local handle the model says it read.  Provenance for an operator,
    #: and checked against the handles this source actually offered.  It is not
    #: part of the signed payload: a receipt carries a proposition, not a
    #: pointer into somebody else's private store.
    basis: str


class ObservationFailure(Enum):
    """Why a candidate did not become a relation.  Every member creates nothing."""

    #: The label is not one this assignment briefed.  The narrowest and most
    #: important refusal in the package: it is how "answer only what you were
    #: asked" is enforced against a model that answers something else.
    UNKNOWN_TARGET = "UNKNOWN_TARGET"
    #: The same target was answered twice.  Refused rather than arbitrated: a
    #: source that says two things about one proposition has not observed one.
    DUPLICATE_TARGET = "DUPLICATE_TARGET"
    #: Not one of the four relation kinds.
    UNKNOWN_RELATION = "UNKNOWN_RELATION"
    #: An ordering relation over a sort that has no order, or a subset over a
    #: sort that is not an enumeration.
    RELATION_NOT_AVAILABLE_FOR_SORT = "RELATION_NOT_AVAILABLE_FOR_SORT"
    #: The value text does not spell a value of the declared sort.
    VALUE_UNPARSABLE = "VALUE_UNPARSABLE"
    #: The value parses and lies outside the declared domain.
    VALUE_OUT_OF_DOMAIN = "VALUE_OUT_OF_DOMAIN"
    #: The observation instant does not parse, or names no offset.
    OBSERVED_AT_UNPARSABLE = "OBSERVED_AT_UNPARSABLE"
    #: The instant parses and lies outside the window this source will stand
    #: behind: after it signed, or further back than it is prepared to attest.
    #:
    #: **This is the only bound on the one field a model authors freely.**  The
    #: label resolves against the assignment, the relation against four
    #: spellings, the value against the pinned sort and domain, the citation
    #: against what was read -- and the instant, left unbounded, decides where
    #: the receipt's validity window *starts*.  A model that back-dated an
    #: observation would widen that window arbitrarily and make the receipt
    #: admissible at case instants the source never observed anything near.
    OBSERVED_AT_OUT_OF_RANGE = "OBSERVED_AT_OUT_OF_RANGE"
    #: The model cited material this source did not offer it.
    BASIS_NOT_OFFERED = "BASIS_NOT_OFFERED"


@dataclass(frozen=True, slots=True)
class ObservationError:
    failure: ObservationFailure
    detail: str


@dataclass(frozen=True, slots=True)
class ValidatedObservation:
    """A candidate that survived: one proposition, one relation, one instant."""

    proposition: SymbolRef
    target: AcquisitionTargetSpec
    relation: AcquisitionRelation
    observed_at: Instant
    basis: str


def validate_candidate(
    candidate: CandidateObservation,
    *,
    targets: dict[str, AcquisitionTargetSpec],
    offered: frozenset[str],
    issued_at: Instant,
    horizon: Instant,
) -> Result[ValidatedObservation, ObservationError]:
    """Turn one candidate into a relation, or refuse it with a reason.

    ``offered`` is the set of references whose octets actually reached the
    interpreter.  A citation outside it means the model referred to material it
    never received -- because the source does not hold it, or because reading it
    failed -- and an observation whose stated basis was never delivered is not
    one this source can stand behind, whatever the value happens to be.

    ``issued_at`` and ``horizon`` bound the observation instant from both ends,
    and both bounds are load-bearing.  A source cannot have observed something
    *after* it signed for it, and a model asked for a timestamp will
    occasionally produce next year's.  Nor may it have observed something
    arbitrarily far *before*: the instant decides where the receipt's validity
    window starts, so an unbounded past would let a model make a receipt
    admissible at case instants this source was never near.  The horizon is the
    source's own configured attestation window, so the bound is a fact about
    what this source is prepared to stand behind rather than a number invented
    here.
    """
    target = targets.get(candidate.label)
    if target is None:
        return Err(
            ObservationError(
                ObservationFailure.UNKNOWN_TARGET,
                f"{candidate.label!r} is not a target of this assignment",
            )
        )
    if candidate.basis not in offered:
        return Err(
            ObservationError(
                ObservationFailure.BASIS_NOT_OFFERED,
                f"{candidate.basis!r} was not offered as local evidence",
            )
        )
    observed_at = _instant_of(candidate.observed_at)
    if observed_at is None:
        return Err(
            ObservationError(ObservationFailure.OBSERVED_AT_UNPARSABLE, candidate.observed_at)
        )
    if observed_at > issued_at:
        return Err(
            ObservationError(
                ObservationFailure.OBSERVED_AT_OUT_OF_RANGE,
                f"{candidate.observed_at} lies after this source signed for it",
            )
        )
    if observed_at < horizon:
        return Err(
            ObservationError(
                ObservationFailure.OBSERVED_AT_OUT_OF_RANGE,
                f"{candidate.observed_at} lies before this source will attest",
            )
        )
    relation = _relation_of(candidate, target.value_sort, target.domain)
    if isinstance(relation, Err):
        return Err(relation.error)
    return Ok(
        ValidatedObservation(
            proposition=target.proposition,
            target=target,
            relation=relation.value,
            observed_at=observed_at,
            basis=candidate.basis,
        )
    )


def validate_all(
    candidates: tuple[CandidateObservation, ...],
    *,
    targets: dict[str, AcquisitionTargetSpec],
    offered: frozenset[str],
    issued_at: Instant,
    horizon: Instant,
) -> Result[tuple[ValidatedObservation, ...], ObservationError]:
    """Every candidate, or the first refusal.

    All-or-nothing here, and per-receipt elsewhere, and the asymmetry is
    deliberate.  A batch of candidates is one model turn: if part of it is
    malformed, the turn is untrustworthy in a way the individual well-formed
    parts do not repair, and signing the good half would be treating a model
    that produced nonsense as a source about everything else it said.
    """
    validated: list[ValidatedObservation] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.label in seen:
            return Err(
                ObservationError(
                    ObservationFailure.DUPLICATE_TARGET,
                    f"{candidate.label!r} was answered more than once",
                )
            )
        seen.add(candidate.label)
        one = validate_candidate(
            candidate,
            targets=targets,
            offered=offered,
            issued_at=issued_at,
            horizon=horizon,
        )
        if isinstance(one, Err):
            return Err(one.error)
        validated.append(one.value)
    return Ok(tuple(validated))


def _relation_of(
    candidate: CandidateObservation, sort: Sort, domain: Domain
) -> Result[AcquisitionRelation, ObservationError]:
    kind = candidate.relation.strip().lower()
    if kind not in RELATION_KINDS:
        return Err(ObservationError(ObservationFailure.UNKNOWN_RELATION, candidate.relation))

    if kind == RELATION_ONE_OF:
        if not isinstance(sort, EnumSort):
            return Err(
                ObservationError(
                    ObservationFailure.RELATION_NOT_AVAILABLE_FOR_SORT,
                    f"one_of needs an enumerated sort, not {sort}",
                )
            )
        return _subset_of(candidate.value, sort, domain)

    if kind in (RELATION_AT_LEAST, RELATION_AT_MOST) and not isinstance(sort, IntSort | ScaledSort):
        #  Q-5, applied one layer early.  An ordering relation over a sort with
        #  no order is refused by the kernel's validator too; refusing here
        #  means the signature is never spent.
        return Err(
            ObservationError(
                ObservationFailure.RELATION_NOT_AVAILABLE_FOR_SORT,
                f"{kind} needs an ordered sort, not {sort}",
            )
        )

    parsed = parse_value(candidate.value, sort)
    if isinstance(parsed, Err):
        return Err(parsed.error)
    value = parsed.value
    if not value_in_domain(value, domain):
        return Err(
            ObservationError(
                ObservationFailure.VALUE_OUT_OF_DOMAIN, f"{candidate.value} is outside {domain}"
            )
        )
    match kind:
        case "exact":
            return Ok(ExactValue(value))
        case "at_least":
            return Ok(ClosedLowerBound(value))
        case _:
            return Ok(ClosedUpperBound(value))


def _subset_of(
    text: str, sort: EnumSort, domain: Domain
) -> Result[AcquisitionRelation, ObservationError]:
    members = tuple(part.strip() for part in text.split(",") if part.strip())
    if not members:
        return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, text))
    if len(set(members)) != len(members):
        return Err(
            ObservationError(ObservationFailure.VALUE_UNPARSABLE, f"{text} repeats a member")
        )
    if not isinstance(domain, EnumDomain):
        return Err(
            ObservationError(
                ObservationFailure.RELATION_NOT_AVAILABLE_FOR_SORT,
                f"{sort} is declared over {domain}",
            )
        )
    values: list[Value] = []
    for member in members:
        value = VEnum(sort.enum_id, member)
        if not value_in_domain(value, domain):
            return Err(
                ObservationError(
                    ObservationFailure.VALUE_OUT_OF_DOMAIN, f"{member} is not a declared member"
                )
            )
        values.append(value)
    try:
        return Ok(EnumSubset(tuple(values)))
    except InvariantViolation as violation:  # pragma: no cover - guarded above
        return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, str(violation)))


def parse_value(text: str, sort: Sort) -> Result[Value, ObservationError]:
    stripped = text.strip()
    match sort:
        case BoolSort():
            spelled = _BOOLEAN_SPELLINGS.get(stripped.lower())
            if spelled is None:
                return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, text))
            return Ok(VBool(spelled))
        case IntSort():
            whole = _integer(stripped)
            if whole is None:
                return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, text))
            return Ok(VInt(whole))
        case ScaledSort(unit_tag, scale):
            minor = _minor_units(stripped, scale)
            if minor is None:
                return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, text))
            return Ok(VScaled(unit_tag, scale, minor))
        case EnumSort(enum_id):
            if not stripped:
                return Err(ObservationError(ObservationFailure.VALUE_UNPARSABLE, text))
            return Ok(VEnum(enum_id, stripped))


def _integer(text: str) -> int | None:
    """A decimal integer and nothing else.

    ``int()`` accepts underscores, surrounding whitespace, a leading plus and
    several Unicode digit forms, so a model producing ``1_000`` or a Devanagari
    numeral would be believed about a quantity.  The character check is what
    makes the accepted spelling one spelling.
    """
    body = text[1:] if text.startswith("-") else text
    if not body or not all(character in "0123456789" for character in body):
        return None
    return int(text)


def _minor_units(text: str, scale: int) -> int | None:
    """A decimal amount, as minor units at the declared scale.

    ``85000`` at scale 2 is not the same claim as ``850.00``, and both are
    spellings a model reaches for.  Only the *major* spelling is accepted --
    an amount with at most ``scale`` fraction digits -- because accepting both
    would make the meaning of an unpunctuated integer depend on which one the
    model happened to intend.
    """
    negative = text.startswith("-")
    body = text[1:] if negative else text
    whole, _, fraction = body.partition(".")
    if not whole or not all(character in "0123456789" for character in whole):
        return None
    if fraction and not all(character in "0123456789" for character in fraction):
        return None
    if len(fraction) > scale:
        return None
    minor: int = int(whole) * (10**scale) + int(fraction.ljust(scale, "0") or "0")
    return -minor if negative else minor


def _instant_of(text: str) -> Instant | None:
    """An ISO-8601 instant that names its offset, as microseconds since the epoch.

    The offset is required.  A timestamp without one is a local reading whose
    meaning depends on where the source is standing, and a source-local
    observation that is ambiguous by twelve hours is not one a case can use.
    """
    try:
        parsed = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return int(parsed.astimezone(UTC).timestamp() * MICROSECONDS)
