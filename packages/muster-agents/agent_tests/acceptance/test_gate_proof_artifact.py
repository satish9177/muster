"""The judge-facing final Gate proof is a transcription, and this checks it.

Nothing in this file re-runs anything.  The five Cloud Run executions it names
finished in a project this suite cannot reach, from an image this worktree is
no longer at, and they will never run again -- which is exactly why the numbers
need a guard.  A transcription has no compiler and no type system; the only
thing standing between "the observed record" and "whatever somebody last typed"
is a test that reads both the source of truth and every place the record is
repeated, and refuses to let them drift.

Three drifts are worth naming, because each has a wrong answer that looks
plausible:

*   **Provenance.**  The deployed image was built from ``af1359c``.  The
    repository moved on to a documentation-only head afterwards, and writing
    that later commit into the image provenance would quietly change which code
    the proof is a proof *of*.  Both commits are recorded, separately, and this
    file checks they stay different and stay in their own fields.

*   **The historical artifact.**  ``ravi-cloud-execution.json`` is an earlier,
    analysis-only run that never opened the Gate.  It still says
    ``NOT_EXECUTED``, and it must: reinterpreting it to match the newer proof
    would be rewriting evidence rather than adding some.

*   **Excluded attempts.**  One earlier execution reached ``UNCERTAIN`` because
    the runtime role lacked ``sandbox_rail`` privileges; it has no attempt row
    and no transfer row and is not an unknown-after-acceptance proof.  It must
    not appear in the published record.
"""

from __future__ import annotations

import json
from pathlib import Path

from demo.gate_proof_artifact import (
    CASE_ID,
    CLOUD_BUILD_ID,
    DEFAULT_OUTPUT,
    DEPLOYED_SOURCE_COMMIT,
    DOCUMENTATION_COMMIT,
    EXECUTION_ID,
    EXTERNAL_REFERENCE,
    IMAGE_DIGEST,
    SCHEMA_VERSION,
    build_gate_proof,
)

REPOSITORY = Path(__file__).resolve().parents[4]
ARCHITECTURE = REPOSITORY / "ARCHITECTURE.md"
README = REPOSITORY / "README.md"
TYPESCRIPT_CONSUMER = REPOSITORY / "packages/muster-ui/src/data/gateProofReadModel.ts"
PROOF_PANEL = REPOSITORY / "packages/muster-ui/src/components/CloudGateProof.tsx"
ANALYSIS_ONLY = REPOSITORY / "packages/muster-ui/public/cases/ravi-cloud-execution.json"

#: The five executions, in the order they happened.
PROOF_EXECUTIONS = (
    "muster-control-plane-hero-z2m6k",
    "muster-database-bootstrap-jkr7k",
    "muster-control-plane-hero-hdfv2",
    "muster-control-plane-hero-pv2f2",
    "muster-database-bootstrap-kpz8p",
)

#: Historical ``UNCERTAIN`` evidence from missing ``sandbox_rail`` runtime
#: privileges.  No attempt row, no transfer row; not a proof of anything the
#: published record claims.
EXCLUDED_EXECUTION = "61bd22835140d6d899dc31def00d35e8eb8f7f8b0c763a2ac51d316be91c9b63"

#: The case that stopped before the Gate when the Site Agent abstained.
EXCLUDED_CASE = "CASE-RAVI-SAT-CLOUD-GATE-FINAL-AF1359C"


def stored() -> dict[str, object]:
    document: object = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_the_tracked_artifact_is_the_transcribed_record() -> None:
    assert stored() == build_gate_proof()


def test_the_deployed_source_commit_is_not_the_documentation_head() -> None:
    provenance = stored()["provenance"]
    assert isinstance(provenance, dict)
    assert provenance["deployed_source_commit"] == DEPLOYED_SOURCE_COMMIT
    assert provenance["documentation_commit"] == DOCUMENTATION_COMMIT
    assert DEPLOYED_SOURCE_COMMIT != DOCUMENTATION_COMMIT
    assert provenance["cloud_build_id"] == CLOUD_BUILD_ID
    assert provenance["image_digest"] == IMAGE_DIGEST
    control_plane_image = provenance["control_plane_image"]
    assert isinstance(control_plane_image, str)
    assert control_plane_image.endswith(f"@{IMAGE_DIGEST}")
    #  A tag would name whatever that tag points at today. Only a digest names
    #  the image the proof actually ran on.
    assert ":latest" not in control_plane_image


def test_the_five_executions_are_named_in_the_observed_order() -> None:
    stages = stored()["stages"]
    assert isinstance(stages, list)
    named = []
    for index, stage in enumerate(stages, start=1):
        assert isinstance(stage, dict)
        assert stage["ordinal"] == index
        named.append(stage["cloud_run_execution"])
    assert tuple(named) == PROOF_EXECUTIONS


def test_one_dispatch_no_redispatch_and_one_surviving_transfer() -> None:
    stages = stored()["stages"]
    assert isinstance(stages, list)
    control_plane = [s for s in stages if isinstance(s, dict) and s["kind"] == "control_plane"]
    external = [s for s in stages if isinstance(s, dict) and s["kind"] == "external_world"]

    assert sum(int(s["dispatches"]) for s in control_plane) == 1
    assert control_plane[0]["dispatches"] == 1
    #  Everything after the answer was lost is observation. A dispatch anywhere
    #  in here would be the retry MUSTER exists not to do.
    assert all(s["dispatches"] == 0 for s in control_plane[1:])
    assert [s["inspections"] for s in control_plane] == [0, 1, 0]

    assert external, "the proof needs independent external-world evidence"
    assert all(s["transfer_count"] == 1 for s in external)
    assert all(s["read_only"] is True for s in external)
    assert all(s["external_reference"] == EXTERNAL_REFERENCE for s in external)


def test_the_uncertainty_and_the_reconciliation_are_exactly_as_observed() -> None:
    stages = stored()["stages"]
    assert isinstance(stages, list)
    unknown, _, reconciliation, idempotent, _ = stages
    assert isinstance(unknown, dict)
    assert isinstance(reconciliation, dict)
    assert isinstance(idempotent, dict)

    assert unknown["state"] == "UNCERTAIN"
    assert unknown["outcome_code"] == "EXECUTOR_EXCEPTION"
    #  An uncertain row has nothing to point at, and printing a receipt for one
    #  would show an outcome the Gate explicitly did not have.
    assert unknown["external_reference"] is None
    assert unknown["real_funds"] is False

    assert reconciliation["state"] == "CONFIRMED"
    assert reconciliation["finality"] == "DEFINITELY_EXECUTED"
    assert reconciliation["reconciled_from"] == "UNCERTAIN"
    assert reconciliation["external_reference"] == EXTERNAL_REFERENCE

    #  The idempotency read reported a state, a reference and two counters. It
    #  reported no finality and no outcome code, so the record carries none.
    assert idempotent["state"] == "CONFIRMED"
    assert idempotent["finality"] is None
    assert idempotent["outcome_code"] is None


def test_the_record_makes_all_four_safety_claims() -> None:
    assert stored()["claims"] == {
        "sandbox_only": True,
        "real_funds": False,
        "live_telemetry": False,
        "cloud_run_process_death_claimed": False,
    }


def test_the_external_reference_is_derived_from_the_execution_identity() -> None:
    document = stored()
    assert document["external_reference"] == f"sandbox-pay-{EXECUTION_ID}"
    assert len(EXECUTION_ID) == 64


def test_excluded_attempts_are_absent_from_the_published_record() -> None:
    text = DEFAULT_OUTPUT.read_text(encoding="utf-8")
    assert EXCLUDED_EXECUTION not in text
    assert EXCLUDED_CASE not in text
    #  The final case name contains the excluded one as a prefix only if the
    #  suffix is dropped, so the identity is asserted whole.
    assert CASE_ID == "CASE-RAVI-SAT-CLOUD-GATE-FINAL-B-AF1359C"


def test_the_architecture_document_records_the_same_identifiers() -> None:
    architecture = ARCHITECTURE.read_text(encoding="utf-8")
    for identifier in (
        CASE_ID,
        EXECUTION_ID,
        DEPLOYED_SOURCE_COMMIT,
        CLOUD_BUILD_ID,
        IMAGE_DIGEST,
        *PROOF_EXECUTIONS,
    ):
        assert identifier in architecture, identifier


def test_the_readme_records_the_provenance_a_judge_checks_first() -> None:
    readme = README.read_text(encoding="utf-8")
    for identifier in (CASE_ID, EXECUTION_ID, DEPLOYED_SOURCE_COMMIT, IMAGE_DIGEST):
        assert identifier in readme, identifier


def test_the_viewer_declares_the_same_schema_version() -> None:
    consumer = TYPESCRIPT_CONSUMER.read_text(encoding="utf-8")
    assert f'GATE_PROOF_SCHEMA_VERSION = "{SCHEMA_VERSION}"' in consumer


def test_the_historical_analysis_only_artifact_is_untouched() -> None:
    """A different run, still saying what it said."""
    historical: object = json.loads(ANALYSIS_ONLY.read_text(encoding="utf-8"))
    assert isinstance(historical, dict)
    assert historical["schema_version"] == "muster.case-trace/v1"
    assert historical["case_id"] == "CASE-RAVI-SAT-CLOUD"
    result = historical["result"]
    assert isinstance(result, dict)
    action = result["action"]
    assert isinstance(action, dict)
    assert action["execution"] == {"status": "NOT_EXECUTED"}
    #  Two different cases, two different documents. If these ever became one
    #  file, the analysis-only run would have been overwritten by the proof.
    assert historical["case_id"] != CASE_ID
    assert ANALYSIS_ONLY != DEFAULT_OUTPUT


def test_the_proof_panel_never_states_the_claims_muster_does_not_make() -> None:
    panel = PROOF_PANEL.read_text(encoding="utf-8")
    lowered = panel.lower()
    #  The disclaimers contain these words; the bare claims must not.
    assert "process death not claimed" in lowered
    assert lowered.count("process death") == lowered.count("process death not claimed")
    for forbidden in ("process was killed", "killed the process", "real payment", "live stream"):
        assert forbidden not in lowered
    for required in (
        "SANDBOX ONLY",
        "NO REAL FUNDS",
        "UNKNOWN AFTER ACCEPTANCE",
        "VERIFIED GCP REPLAY — NOT LIVE TELEMETRY",
    ):
        assert required in panel, required
