"""The eight interpretation cases, as data.

Each case is a directory of synthetic material plus the one answer a competent
source-local interpreter would give.  Written as data rather than as tests so
that the deterministic run and the live-model run are the *same* expectations
read twice, and a case added here is added to both.

**Abstention is the expected answer in four of the eight.**  That ratio is the
point: an interpreter that always answers is worse than one that answers four
times out of eight and declines the rest, because four of these cases have no
answer the material supports.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from agent_tests.support.fleet import SITE_MATERIAL
from muster.core.evidence.acquisition import AbstentionReason


@dataclass(frozen=True, slots=True)
class Expected:
    """What a correct interpreter produces for one case.

    Either observations -- a mapping from predicate to the relation and value
    the material supports -- or an abstention naming why.  Never both, and
    never "either would be acceptable": a case with two acceptable answers is a
    case that measures nothing.
    """

    observations: dict[str, tuple[str, str]] | None = None
    abstention: AbstentionReason | None = None

    def __post_init__(self) -> None:
        assert (self.observations is None) != (self.abstention is None), self


@dataclass(frozen=True, slots=True)
class Case:
    """One evaluation case: a name, some material, and the right answer."""

    name: str
    why: str
    subject: str
    #: The gate log this case offers.  ``bytes`` where the case is about a
    #: file that is not readable text, because a corrupt export has to be
    #: actually corrupt to be worth testing.
    gate_log: str | bytes | None
    #: Whether the attendance photograph is present.  A case about corrupt or
    #: missing media says so by leaving it out or replacing it.
    board: bool
    expected: Expected

    def materialise(self, root: Path) -> Path:
        """Write this case's material into a directory of its own."""
        directory = root / self.name
        directory.mkdir(parents=True, exist_ok=True)
        items: list[dict[str, object]] = []
        if self.gate_log is not None:
            octets = (
                self.gate_log if isinstance(self.gate_log, bytes) else self.gate_log.encode("utf-8")
            )
            (directory / "gate-log-sat.txt").write_bytes(octets)
            items.append(
                {
                    "ref": "gate-log-sat",
                    "media_type": "text/plain",
                    "label": "North gate access-control export, Saturday",
                    "file": "gate-log-sat.txt",
                    "subject": self.subject,
                    "scope": [{"kind": "SITE", "value": "SITE-A"}],
                }
            )
        if self.board:
            shutil.copyfile(
                SITE_MATERIAL / "attendance-board-sat.png",
                directory / "attendance-board-sat.png",
            )
            items.append(
                {
                    "ref": "attendance-board-sat",
                    "media_type": "image/png",
                    "label": "North gate attendance board, Saturday",
                    "file": "attendance-board-sat.png",
                    "subject": self.subject,
                    "scope": [{"kind": "SITE", "value": "SITE-A"}],
                }
            )
        (directory / "manifest.json").write_text(
            json.dumps({"items": items}, indent=2) + "\n", encoding="utf-8"
        )
        return directory


_HEADER = (
    "SITE-A / NORTH GATE / ACCESS CONTROL SYSTEM\n"
    "exported 2026-08-01T18:02:11+00:00 by gate-ctl 4.2.1\n"
    "\nbadge,worker,event,timestamp,reader\n"
)

FULL_DAY = _HEADER + (
    "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2\n"
    "B-4471,RAVI,OUT,2026-08-01T17:40:52+00:00,NORTH-TURNSTILE-2\n"
)

SHORT_VISIT = _HEADER + (
    "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2\n"
    "B-4471,RAVI,OUT,2026-08-01T10:41:07+00:00,NORTH-TURNSTILE-2\n"
)

SOMEBODY_ELSE = _HEADER + (
    "B-2210,PRIYA,IN,2026-08-01T08:55:31+00:00,NORTH-TURNSTILE-1\n"
    "B-2210,PRIYA,OUT,2026-08-01T13:05:02+00:00,NORTH-TURNSTILE-1\n"
)

NOBODY = _HEADER + "\n(no access events recorded for this reader on this date)\n"

HALF_AN_ENTRY = _HEADER + (
    "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2\n"
    "(export truncated: reader NORTH-TURNSTILE-2 lost power at 12:03; no exit "
    "events were captured after that time)\n"
)

CONTRADICTORY = _HEADER + (
    "B-4471,RAVI,IN,2026-08-01T09:12:04+00:00,NORTH-TURNSTILE-2\n"
    "B-4471,RAVI,OUT,2026-08-01T17:40:52+00:00,NORTH-TURNSTILE-2\n"
    "\n--- reconciliation note, appended by site supervisor ---\n"
    "The north gate reader was under maintenance all day on 2026-08-01 and its\n"
    "clock and badge mapping cannot be relied on. The manual sign-in sheet for\n"
    "2026-08-01 records RAVI as absent.\n"
)

#  Genuinely not UTF-8, rather than a string that looks corrupt.  A decoder is
#  either given octets it cannot read or it is not, and the second is not a test.
CORRUPT = _HEADER.encode("utf-8") + b"\x00\x01\x02\xff\xfe corrupt block \x00\x00\n"


CASES: tuple[Case, ...] = (
    Case(
        name="clearly-present-full-day",
        why="an entry and an exit eight hours apart: the worked case",
        subject="RAVI",
        gate_log=FULL_DAY,
        board=True,
        expected=Expected(
            observations={
                "present_on_site": ("exact", "true"),
                "on_site_duration": ("at_least", "240"),
            }
        ),
    ),
    Case(
        name="present-but-under-the-threshold",
        why=(
            "an hour and a half on site.  Presence is still true and the "
            "duration bound is genuinely below four hours -- a source reports "
            "what it saw, and the policy decides what that is worth"
        ),
        subject="RAVI",
        gate_log=SHORT_VISIT,
        board=False,
        expected=Expected(
            observations={
                "present_on_site": ("exact", "true"),
                "on_site_duration": ("at_most", "89"),
            }
        ),
    ),
    Case(
        name="clearly-absent",
        why="the reader recorded nothing for anybody",
        subject="RAVI",
        gate_log=NOBODY,
        board=False,
        expected=Expected(observations={"present_on_site": ("exact", "false")}),
    ),
    Case(
        name="wrong-person",
        why=(
            "somebody was on site all morning and it was not the subject.  The "
            "sharpest failure a helpful interpreter makes"
        ),
        subject="RAVI",
        gate_log=SOMEBODY_ELSE,
        board=False,
        expected=Expected(abstention=AbstentionReason.SUBJECT_NOT_IDENTIFIED),
    ),
    Case(
        name="insufficient-for-a-duration",
        why=(
            "an entry, no exit, and a reader that lost power.  Presence is "
            "supported; a duration is not, and inventing one is exactly the "
            "inference the brief forbids"
        ),
        subject="RAVI",
        gate_log=HALF_AN_ENTRY,
        board=False,
        expected=Expected(observations={"present_on_site": ("exact", "true")}),
    ),
    Case(
        name="contradictory",
        why="the badge log and the sign-in sheet disagree; arbitrating is not a source's job",
        subject="RAVI",
        gate_log=CONTRADICTORY,
        board=False,
        expected=Expected(abstention=AbstentionReason.EVIDENCE_CONTRADICTORY),
    ),
    Case(
        name="corrupt-export",
        why="the export is not readable text; a lossy decode would be a confident misreading",
        subject="RAVI",
        gate_log=CORRUPT,
        board=False,
        expected=Expected(abstention=AbstentionReason.EVIDENCE_UNREADABLE),
    ),
    Case(
        name="no-material-at-all",
        why="this source holds nothing about this subject at this resource",
        subject="RAVI",
        gate_log=None,
        board=False,
        expected=Expected(abstention=AbstentionReason.EVIDENCE_NOT_FOUND),
    ),
)
