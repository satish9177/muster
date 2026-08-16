"""Malformed input reaches a typed rejection, never a traceback.

The parser is the only place untrusted text enters the system, and the CLI's
promise is that a bad file exits with a code rather than a stack trace.  These
mutations of the Ravi fixture are each one field wrong; every one of them used
to escape as ``ValueError`` or ``InvariantViolation``, because the loader caught
only its own rejection type.

They are driven through ``load_case_file`` *and* ``main``, because the defect
was invisible at the level of the individual readers.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from muster.application.case_file import CaseFileFailure, load_case_file, load_engine_limits
from muster.application.cli import EXIT_REJECTED, EXIT_USAGE, main
from muster.core.results import Err, Ok
from tests.support import ravi

type Mutation = Callable[[dict[str, Any]], None]

MUTATIONS: dict[str, Mutation] = {
    "nonce-is-not-hex": lambda d: d["transcript"][0].__setitem__("nonce", "zz" * 16),
    "nonce-is-odd-length": lambda d: d["transcript"][0].__setitem__("nonce", "abc"),
    "nonce-is-the-wrong-width": lambda d: d["transcript"][0].__setitem__("nonce", "00" * 8),
    "scale-is-negative": lambda d: d["transcript"][0]["value_sort"].__setitem__("scale", -5),
    "enum-subset-is-empty": lambda d: d["transcript"][0].__setitem__(
        "relation", {"kind": "enum_subset", "allowed": []}
    ),
    "unknown-top-level-key": lambda d: d.__setitem__("surprise", 1),
    "unknown-entry-key": lambda d: d["transcript"][0].__setitem__("surprise", 1),
    "misspelled-required-key": lambda d: d.__setitem__("tenant_i", d.pop("tenant_id")),
    "as_of-is-a-string": lambda d: d.__setitem__("as_of", "yesterday"),
    "as_of-is-a-boolean": lambda d: d.__setitem__("as_of", True),
    "mode-is-not-a-declared-member": lambda d: d.__setitem__("mode", "SPECULATIVE"),
    "relation-kind-is-unknown": lambda d: d["transcript"][0]["relation"].__setitem__(
        "kind", "approximately"
    ),
    "sort-kind-is-unknown": lambda d: d["transcript"][0]["value_sort"].__setitem__(
        "kind", "quaternion"
    ),
    "entry-kind-is-unknown": lambda d: d["transcript"][0].__setitem__("kind", "rumour"),
    "digest-is-the-wrong-length": lambda d: d["transcript"][0].__setitem__(
        "predicate_schema_digest", "ab"
    ),
    "digest-is-not-hex": lambda d: d["transcript"][0].__setitem__(
        "predicate_schema_digest", "z" * 64
    ),
    "validity-is-empty": lambda d: d["transcript"][0].__setitem__(
        "validity", {"start": 10, "end": 10}
    ),
    "declared-instance-is-not-an-object": lambda d: d["declared_instances"].append(42),
    "transcript-is-not-a-list": lambda d: d.__setitem__("transcript", {}),
    "parties-entry-is-not-an-object": lambda d: d["case_construction"]["parties"].append("RAVI"),
}


def _mutated(tmp_path: Path, name: str, mutate: Mutation) -> Path:
    document = json.loads(ravi.CASE_FILE.read_text(encoding="utf-8"))
    mutate(document)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_a_malformed_case_file_is_a_typed_rejection(name: str, tmp_path: Path) -> None:
    outcome = load_case_file(_mutated(tmp_path, name, MUTATIONS[name]))
    assert isinstance(outcome, Err), f"{name} was accepted"
    assert isinstance(outcome.error.failure, CaseFileFailure)
    assert outcome.error.path


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_the_cli_exits_rather_than_aborting(name: str, tmp_path: Path) -> None:
    """The defect this catches printed a traceback and exited non-deterministically."""
    path = _mutated(tmp_path, name, MUTATIONS[name])
    assert main(["analyse", "--case", str(path), "--config", str(ravi.LIMITS_FILE)]) == (
        EXIT_REJECTED
    )


def test_the_unmodified_fixture_is_still_accepted(tmp_path: Path) -> None:
    """The control: every mutation above starts from a file that loads."""
    del tmp_path
    assert isinstance(load_case_file(ravi.CASE_FILE), Ok)


def test_a_missing_file_is_unreadable_not_malformed() -> None:
    """Saying "malformed JSON" about a file that does not exist is a false report."""
    outcome = load_case_file(Path("no-such-case.json"))
    assert isinstance(outcome, Err)
    assert outcome.error.failure is CaseFileFailure.UNREADABLE


def test_a_file_that_is_not_json_is_malformed() -> None:
    outcome = load_case_file(ravi.LIMITS_FILE.parent / "ravi-saturday.json")
    assert isinstance(outcome, Ok)


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("missing-bound", lambda d: d.pop("max_unresolved")),
        ("zero-bound", lambda d: d.__setitem__("max_unresolved", 0)),
        ("negative-bound", lambda d: d.__setitem__("reachable_action_cap", -1)),
        ("unknown-key", lambda d: d.__setitem__("max_everything", 1)),
        ("bound-is-a-string", lambda d: d.__setitem__("max_unresolved", "lots")),
    ],
)
def test_engine_configuration_is_a_startup_failure_when_it_is_not_usable(
    name: str, mutate: Mutation, tmp_path: Path
) -> None:
    """There is no default bound to fall back to, deliberately."""
    document = json.loads(ravi.LIMITS_FILE.read_text(encoding="utf-8"))
    mutate(document)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    assert isinstance(load_engine_limits(path), Err)
    assert main(["analyse", "--case", str(ravi.CASE_FILE), "--config", str(path)]) == (
        EXIT_REJECTED
    )


def test_a_missing_configuration_file_is_a_startup_failure() -> None:
    assert main(["analyse", "--case", str(ravi.CASE_FILE), "--config", "absent.json"]) == (
        EXIT_REJECTED
    )


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["analyse"],
        ["analyse", "--case"],
        ["analyse", "--case", "a.json"],
        ["analyse", "--case", "a.json", "--config"],
        ["analyse", "--case", "a.json", "--config", "b.json", "--extra"],
        ["analyse", "--unknown", "x", "--config", "b.json"],
        ["explain", "--case", "a.json", "--config", "b.json"],
    ],
)
def test_a_malformed_command_line_is_a_usage_error(argv: list[str]) -> None:
    assert main(argv) == EXIT_USAGE
