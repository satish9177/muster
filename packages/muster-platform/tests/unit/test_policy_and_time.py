"""The operator numbers that have no defaults, and the two time types.

There is no clock test here, and there is no clock.  ``adapters.clock`` held a
``Clock`` protocol, a ``SystemClock`` and a ``FixedClock``, and across the whole
milestone nothing imported any of them except this file: every command takes
``now`` as an argument, so the reading is supplied by whoever is at the
imperative boundary and the package never takes one for itself.  An abstraction
whose only caller is its own test is not a boundary, it is a decision taken
early about a component that does not exist yet -- and it was carrying an
architecture rule ("the clock is confined to one module") that stopped meaning
anything the moment the module had nothing in it to confine.

What replaced it is a rule with a stronger shape: *no* module in this package
may import an ambient source of time, and ``test_boundaries`` checks that from
the source.  A future milestone that needs a clock adds one module and one
exemption, in a diff somebody reviews.
"""

from __future__ import annotations

import pytest

from muster.core.results import InvariantViolation
from muster.core.values.times import Duration, Instant
from muster.platform.casework.advance import CaseworkPolicy

ONE_HOUR = Duration(3_600 * 1_000_000)


@pytest.mark.parametrize("attempts", [0, -1])
def test_a_policy_that_would_never_publish_is_refused(attempts: int) -> None:
    with pytest.raises(InvariantViolation):
        CaseworkPolicy(max_publication_attempts=attempts, evidence_request_ttl=Duration(1))


def test_a_deadline_that_is_already_past_is_refused() -> None:
    with pytest.raises(InvariantViolation):
        CaseworkPolicy(max_publication_attempts=1, evidence_request_ttl=Duration(0))


def test_the_policy_has_no_defaults() -> None:
    """An unbounded retry and an absent deadline both look like working software.

    They stop looking like it on the day a case is contended or a source goes
    quiet, which is the worst possible day to discover the number was never
    chosen.
    """
    with pytest.raises(TypeError):
        CaseworkPolicy()  # type: ignore[call-arg]


#  ---- Duration is not an Instant -------------------------------------------


def test_a_duration_is_not_an_integer_and_cannot_stand_in_for_an_instant() -> None:
    """The runtime half of the distinction the type checker enforces statically.

    ``Instant`` is an alias for ``int``, so a TTL that was also an ``int``
    satisfied every signature an instant did. The class does not, and it does
    not subclass ``int`` either -- which it would have to, to slip through the
    same holes.

    The *static* half of this is enforced by the quality gate rather than by an
    assertion here. ``mypy --strict`` reports an unused ``type: ignore``, so the
    ``# type: ignore[arg-type]`` comments in ``test_decide`` on the two swapped
    calls fail the build the day ``Duration`` and ``Instant`` become compatible
    again -- a suppression that stops being needed is an error, which is exactly
    the alarm this distinction wants.
    """
    #  Typed ``object`` so the check is a real one: with ``Duration`` in the
    #  annotation the type checker already knows the answer and refuses to
    #  compile the question, which is itself the static half of the claim.
    ttl: object = ONE_HOUR
    assert not isinstance(ttl, int)
    assert int not in Duration.__mro__

    now: Instant = 1_760_000_000_000_000
    with pytest.raises(TypeError):
        assert now + ttl  # type: ignore[operator]
    with pytest.raises(TypeError):
        assert ttl < now  # type: ignore[operator]


def test_a_duration_refuses_a_negative_count_at_construction() -> None:
    """A duration is a magnitude. The direction belongs to whatever applies it."""
    with pytest.raises(InvariantViolation):
        Duration(-1)
    assert Duration(0).microseconds == 0
    assert not Duration(0).is_positive()
    assert ONE_HOUR.is_positive()


def test_applying_a_duration_is_explicit_and_directional() -> None:
    now: Instant = 1_760_000_000_000_000
    assert ONE_HOUR.after(now) == now + 3_600_000_000
    #  There is no ``before``: nothing in this system dates anything backwards,
    #  and an operation nobody needs is an operation nobody has checked.
    assert not hasattr(ONE_HOUR, "before")


def test_two_durations_of_the_same_length_are_the_same_value() -> None:
    """Immutable and compared by value, so a policy is a value and not a handle."""
    assert Duration(5) == Duration(5)
    assert Duration(5) != Duration(6)
    assert {Duration(5), Duration(5)} == {Duration(5)}
    with pytest.raises(AttributeError):
        ONE_HOUR.microseconds = 1  # type: ignore[misc]


#  ---- a durable instant fits in the column that holds it --------------------


def test_a_deadline_outside_the_durable_range_is_refused_by_the_value() -> None:
    """Checked in the value type, so both adapters refuse the same input.

    Python integers are unbounded; ``deadline bigint`` is not. Without this,
    a TTL large enough to push a deadline past ``2**63`` is recorded happily by
    the in-memory adapter and raises ``NumericValueOutOfRange`` from PostgreSQL
    -- an untyped driver exception, raised in TX B, *after* TX A has already
    made the entry durable. A misconfigured TTL is an ordinary way to produce
    one, and the two adapters disagreeing about it is exactly the divergence
    the shared contract exists to prevent.
    """
    from muster.core.wire.digests import Digest
    from muster.platform.casework.ports import RecordedRequest

    inside = RecordedRequest(
        case_id="case-range",
        request_id=Digest(b"\x01" * 32),
        revision_digest=Digest(b"\x02" * 32),
        deadline=2**63 - 1,
    )
    assert inside.deadline == 2**63 - 1

    for outside in (2**63, -(2**63) - 1, ONE_HOUR.after(2**63)):
        with pytest.raises(InvariantViolation):
            RecordedRequest(
                case_id="case-range",
                request_id=Digest(b"\x01" * 32),
                revision_digest=Digest(b"\x02" * 32),
                deadline=outside,
            )
