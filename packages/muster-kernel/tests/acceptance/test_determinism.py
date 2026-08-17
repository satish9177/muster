"""Determinism, anchored and checked across processes.

Comparing a run to itself inside one process proves almost nothing: a canonical
ordering that is deterministic-but-wrong passes, and one that depends on string
hashing passes too, because the seed is fixed for the life of the interpreter.

So there are two checks here.  A **frozen anchor**: the Ravi artifacts have
these digests, and any change to a canonical ordering, a digest domain or a
derivation moves them.  And a **cross-process** comparison under different
``PYTHONHASHSEED`` values, which is what catches an ordering that quietly came
from a set or a dict.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import PACKAGE_ROOT
from tests.support import ravi

#  Frozen for this milestone. If a change is deliberate, these move with it and
#  the move is visible in the diff -- which is the point.
RAVI_REVISION_DIGEST = "51438b713114d3becc772a840a49f8b46c8cd213adf74d237cb10dd8bdec34a7"
RAVI_LOGICAL_CASE_DIGEST = "14729c8dbca70a6ea3272b025af278c74ce77fac1714ab59f458fc8952a64e8e"
#  Moved once, deliberately: the encoder used to bind only the enums a declared
#  *variable* carried, so the Ravi queries mentioned ``party_id`` -- the enum the
#  payment's recipient is a constant of -- without declaring it. The queries now
#  bind every enum they mention, which changes the query octets and therefore the
#  kernel record and the certificate that cites it.
#  Previous value: d819536b9f3345368231f65c125494b84726fdcb80612dbd34a2f539a7f6b359
RAVI_CERTIFICATE_DIGEST = "53f6f155a2fe67f0725671e2b9e3163c7bb4a531892db73b5e55109837b56a23"
WORKFORCE_MANIFEST_DIGEST = "a6f51be4d74e3470fdba490d9d7e9ba0b79fbee5daf399a43f9692ee81dc4b11"

HASH_SEEDS = ("0", "1", "99991")


def test_the_bundle_has_its_frozen_digest() -> None:
    """The manifest pins every subartifact, so this moves if any of them does."""
    assert ravi.bundle().digest().hex == WORKFORCE_MANIFEST_DIGEST


def test_the_revision_has_its_frozen_digest() -> None:
    """The identity every downstream artifact cites.

    A reversed sort key inside a premise-digest list, or a collection ordered by
    discovery rather than canonically, changes this and nothing else would
    notice.
    """
    assert ravi.revision().digest().hex == RAVI_REVISION_DIGEST


def test_the_logical_case_and_certificate_have_their_frozen_digests() -> None:
    analysis = ravi.analysis()
    assert analysis.projected.logical.digest().hex == RAVI_LOGICAL_CASE_DIGEST
    assert analysis.certificate.digest().hex == RAVI_CERTIFICATE_DIGEST


def _run(case: Path, seed: str) -> str:
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = seed
    environment["PYTHONPATH"] = str(PACKAGE_ROOT / "src")
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "muster.application.cli",
            "analyse",
            "--case",
            str(case),
            "--config",
            str(ravi.LIMITS_FILE),
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=True,
        cwd=str(PACKAGE_ROOT),
    )
    return completed.stdout


@pytest.mark.parametrize(
    "case",
    ["ravi-saturday.json", "ravi-saturday-attested.json", "ravi-saturday-forged-normative.json"],
)
def test_the_report_is_identical_across_processes_and_hash_seeds(case: str) -> None:
    """An ordering that came from a set would differ between these runs."""
    path = ravi.CASE_FILE.parent / case
    outputs = {seed: _run(path, seed) for seed in HASH_SEEDS}
    first = outputs[HASH_SEEDS[0]]
    assert first.strip()
    for seed, output in outputs.items():
        assert output == first, f"PYTHONHASHSEED={seed} produced a different report"


def test_the_anchored_digests_appear_in_the_report() -> None:
    """The report and the in-process artifacts agree, so neither can drift alone."""
    report = _run(ravi.CASE_FILE, "0")
    assert RAVI_REVISION_DIGEST in report
    assert RAVI_LOGICAL_CASE_DIGEST in report
    assert RAVI_CERTIFICATE_DIGEST in report
    assert WORKFORCE_MANIFEST_DIGEST in report
