"""Finding a ``bash`` that can actually run these tests' driver scripts.

``shutil.which("bash")`` is the obvious call and it is wrong on Windows.  What
it finds first is one of the WSL launchers -- ``System32\\bash.exe``, or the app
execution alias under ``WindowsApps`` -- and neither is a shell.  Each starts a
Linux distribution with its own filesystem, so a driver script this suite writes
into ``tmp_path`` and hands over as ``C:/Users/.../drive.sh`` does not exist for
it.  Every shell test then fails at once, with a hundred tracebacks that say
nothing about the deployment scripts they were checking, and real failures hide
in the noise.

The fix is not a list of bad directories.  There turned out to be two of those
already, and a blocklist is only ever correct until the next one ships.  So the
question asked here is the one the callers actually need answered: *can this
program run a script named by a path from this filesystem?*  Candidates are
tried in ``PATH`` order and each is handed a one-line script exactly the way the
tests hand over theirs; the first that runs it and prints back what it was told
to print is the shell.

Returning ``None`` still means *skip*, not *pass*.  A machine with no POSIX
shell cannot check a claim about shell scripts, and saying so is honest; what
this must never do is let a suite go green by finding a shell that silently ran
nothing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from functools import cache
from pathlib import Path

#: What the probe script prints.  A distinctive marker, so a shell that produces
#: a banner, a warning or an empty answer cannot be mistaken for one that ran it.
PROBE_MARK = "muster-posix-shell-ok"

#: Long enough for a cold interpreter on a loaded machine, short enough that a
#: launcher which blocks waiting on something does not hang the suite.
PROBE_TIMEOUT_SECONDS = 30


@cache
def posix_shell() -> str | None:
    """The first ``bash`` on ``PATH`` that runs a script named by a real path."""
    for candidate in _candidates():
        if _runs_a_script(candidate):
            return candidate
    return None


def _candidates() -> Iterator[str]:
    """Every distinct ``bash`` on ``PATH``, in ``PATH`` order."""
    seen: set[str] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        found = shutil.which("bash", path=directory)
        if found is None:
            continue
        key = os.path.normcase(found)
        if key in seen:
            continue
        seen.add(key)
        yield found


def _runs_a_script(candidate: str) -> bool:
    """Hand it a script the way the tests do, and see whether it ran it."""
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "probe.sh"
        script.write_bytes(f"printf '%s' {PROBE_MARK}\n".encode())
        try:
            done = subprocess.run(  # noqa: S603 - a program from PATH, a generated script
                [candidate, script.as_posix()],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
    return done.returncode == 0 and done.stdout.strip() == PROBE_MARK
