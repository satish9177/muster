"""Where things are.

Kept out of ``conftest.py`` on purpose.  Two packages in this workspace have a
``tests`` directory, so the platform suite is rooted at its own ``tests``
directory rather than one level above it -- ``support``, ``unit`` and the rest
are the top-level test packages, and there is no importable ``tests`` package
here to collide with the kernel's.  A module importing ``conftest`` by name
would undo that, so the constants live here where a normal import reaches them.
"""

from __future__ import annotations

from pathlib import Path

#  .../packages/muster-platform/tests/support/paths.py -> the repository root.
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
PACKAGE_ROOT = Path(__file__).resolve().parents[2]

#  The Ravi fixture has one home, in the kernel package, and this suite reads
#  it rather than restating it: the claim under test is that both paths reach
#  the same answer from the same case, and two copies of the case would be two
#  cases.
KERNEL_FIXTURES = REPOSITORY_ROOT / "packages" / "muster-kernel" / "fixtures"
