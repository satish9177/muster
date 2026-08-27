"""The cloud hero's synthetic source trust is stable and tightly scoped."""

from __future__ import annotations

from dataclasses import replace

from demo.cloud_hero import CloudFleet, HeroMode, _stable_hero_sources, cloud_case
from demo.stable_keys import _public_key

from muster.core.evidence.signing import attestation_preimage
from muster.core.evidence.transcript import Attestation, entry_digest
from muster.platform.adapters.crypto import LocalEcdsaSourceVerifier
from muster.platform.adapters.sql.config import DatabaseDeployment
from support import ravi
from support.authority import SOURCE_KEYS


def _fleet() -> CloudFleet:
    return CloudFleet(
        tenant_id="ALPHA",
        case_id="CASE-RAVI-STABLE-SOURCES",
        site_endpoint="https://site.example.run.app",
        employer_endpoint="https://employer.example.run.app",
        site_key_ref="site-key/deployed-1",
        employer_key_ref="employer-key/deployed-1",
        site_public_key=b"deployed site public key",
        employer_public_key=b"deployed employer public key",
        timeout_seconds=None,
        raw_object=None,
        postgres=None,
        deployment=DatabaseDeployment.EPHEMERAL,
        gate_mode=HeroMode.ANALYSIS_ONLY,
        gate_principal=None,
        gate_execution_key=None,
    )


def test_cloud_case_sources_are_process_stable_and_verify() -> None:
    fleet = _fleet()
    first = cloud_case(fleet)
    second = cloud_case(fleet)

    assert tuple(entry_digest(entry) for entry in first.entries) == tuple(
        entry_digest(entry) for entry in second.entries
    )

    verifier = LocalEcdsaSourceVerifier(
        {key_ref: _public_key("source", key_ref) for key_ref in SOURCE_KEYS}
    )
    attestations = tuple(entry for entry in first.entries if isinstance(entry, Attestation))
    assert attestations
    for entry in attestations:
        receipt = entry.receipt
        assert verifier.verify(
            key_ref=receipt.payload.signer_key_ref,
            preimage=attestation_preimage(receipt.payload),
            signature=receipt.signature,
        )


def test_deployed_refs_are_not_derived() -> None:
    fleet = _fleet()
    base = ravi.ravi(fleet.tenant_id, fleet.case_id)
    fixture = next(entry for entry in base.entries if isinstance(entry, Attestation))
    deployed_entries = tuple(
        Attestation(
            replace(
                fixture.receipt,
                payload=replace(fixture.receipt.payload, signer_key_ref=key_ref),
            )
        )
        for key_ref in (fleet.site_key_ref, fleet.employer_key_ref)
    )
    case = replace(base, entries=deployed_entries)

    stable = _stable_hero_sources(case)

    assert stable.entries == deployed_entries
