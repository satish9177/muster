"""The two time values, and the arithmetic that is allowed between them.

``Instant`` is an alias for ``int`` and stays one: it is a rebuild input, it is
a wire integer, and wrapping it would put a constructor between the codec and
every timestamp in the system for no gain.  ``Duration`` is a class, because
the *pair* is what needs to be distinguishable and only one of them has to
carry the distinction.
"""

from __future__ import annotations

import pytest

from muster.core.results import InvariantViolation
from muster.core.values.times import Duration, HalfOpenInterval, Instant, read_half_open

ONE_HOUR = Duration(3_600 * 1_000_000)
EPOCH_ADJACENT: Instant = 1_760_000_000_000_000


def test_a_duration_is_a_length_and_an_instant_is_a_point() -> None:
    """The whole reason the class exists, as a runtime fact.

    Before this type there was one spelling for both, so ``now + ttl`` and
    ``ttl + now`` were the same expression and a signature could not tell a
    caller which it wanted.
    """
    assert int not in Duration.__mro__
    assert ONE_HOUR.after(EPOCH_ADJACENT) == EPOCH_ADJACENT + 3_600_000_000
    with pytest.raises(TypeError):
        assert EPOCH_ADJACENT + ONE_HOUR  # type: ignore[operator]


@pytest.mark.parametrize("microseconds", [-1, -1_000, -3_600_000_000])
def test_a_negative_duration_cannot_be_constructed(microseconds: int) -> None:
    """A magnitude, so the sign is not part of it. The direction is ``after``."""
    with pytest.raises(InvariantViolation):
        Duration(microseconds)


def test_the_zero_duration_exists_and_says_it_is_not_positive() -> None:
    """Zero is a length. Whether it is an acceptable deadline is a policy question.

    Kept separate on purpose: the type refuses what cannot be a duration, and
    the operator's policy refuses what cannot be a deadline. Folding the second
    into the first would make ``Duration`` mean "a usable TTL", which is not
    what a duration is.
    """
    assert Duration(0).microseconds == 0
    assert not Duration(0).is_positive()
    assert Duration(1).is_positive()


def test_durations_are_immutable_values_compared_by_length() -> None:
    assert Duration(5) == Duration(5)
    assert Duration(5) != Duration(6)
    assert len({Duration(5), Duration(5), Duration(6)}) == 2
    with pytest.raises(AttributeError):
        ONE_HOUR.microseconds = 1  # type: ignore[misc]


def test_a_duration_has_no_wire_form() -> None:
    """Nothing durable holds one, so it has no format to keep compatible.

    An evidence request stores the ``Instant`` its deadline resolved to. The
    policy that produced it is configuration, and configuration is not history.
    """
    assert not hasattr(Duration, "to_node")
    assert not hasattr(Duration, "digest")


#  ---- the interval, which is two instants and not a duration ----------------


def test_a_validity_interval_is_a_pair_of_instants() -> None:
    interval = HalfOpenInterval(EPOCH_ADJACENT, ONE_HOUR.after(EPOCH_ADJACENT))
    assert interval.contains(EPOCH_ADJACENT)
    assert not interval.contains(ONE_HOUR.after(EPOCH_ADJACENT))
    assert read_half_open(interval.to_node()) == interval


def test_an_open_ended_interval_never_expires() -> None:
    interval = HalfOpenInterval(EPOCH_ADJACENT)
    assert interval.contains(ONE_HOUR.after(EPOCH_ADJACENT))
    assert read_half_open(interval.to_node()) == interval


def test_an_empty_interval_is_refused() -> None:
    with pytest.raises(InvariantViolation):
        HalfOpenInterval(EPOCH_ADJACENT, EPOCH_ADJACENT)
