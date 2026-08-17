"""Admitting canonical octets to the store.

Two rules, and the second one is the reason this is a module rather than three
lines inside a command.

**The octets are the artifact.**  Everything here takes octets, decodes them to
check what they are, and then stores *the octets it was given* -- never a
re-encoding of what it decoded.  A decode-then-re-encode admission path
silently canonicalises a non-canonical input, which changes its digest, which
means the artifact stored is not the artifact anybody signed.  The check that
makes this real is the equality assertion below: the octets must already be
what the encoder would produce.  Today every caller hands over octets this
package encoded a moment earlier and the check cannot fail; the day a transport
hands over octets from the network, it is the only thing standing between a
forgiving parser and a wrong digest.

**Binding is checked before storage, not after.**  An entry carries its own
tenant and case inside the octets a signature will eventually cover.  Those
have to match the case being appended to, and the mismatch has to be refused
here -- ``rebuild`` also refuses it, but refusing at admission means a
cross-tenant entry never becomes durable at all.

**Signatures are carried, not verified.**  This milestone holds no keyring, the
same as the one before it.  Nothing admitted here may be read as evidence that
an entry came from the principal it names.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.evidence.transcript import (
    Attestation,
    CaseConstructionRecord,
    Statement,
    TranscriptEntry,
    entry_node,
    read_entry,
)
from muster.core.results import Err, Ok, Result
from muster.core.wire.codec import decode, encode
from muster.core.wire.digests import Digest, DigestKind
from muster.core.wire.shape import decoded
from muster.platform.casework.ports import StoreError, TenantScope


class AdmissionFailure(Enum):
    NOT_CANONICAL = "NOT_CANONICAL"
    NOT_A_TRANSCRIPT_ENTRY = "NOT_A_TRANSCRIPT_ENTRY"
    #  The octets decode, and re-encoding them produces something else. The
    #  input was a non-canonical spelling of a value, and storing it would put
    #  two octet strings under one meaning.
    RE_ENCODES_DIFFERENTLY = "RE_ENCODES_DIFFERENTLY"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    CASE_MISMATCH = "CASE_MISMATCH"
    STORE_REFUSED = "STORE_REFUSED"


@dataclass(frozen=True, slots=True)
class AdmissionError:
    failure: AdmissionFailure
    detail: str


@dataclass(frozen=True, slots=True)
class AdmittedEntry:
    entry: TranscriptEntry
    entry_digest: Digest


def admit_entry(
    scope: TenantScope, case_id: str, entry: TranscriptEntry
) -> Result[AdmittedEntry, AdmissionError]:
    """Admit an entry this process holds as a value."""
    return admit_entry_octets(scope, case_id, encode(entry_node(entry)))


def admit_entry_octets(
    scope: TenantScope, case_id: str, octets: bytes
) -> Result[AdmittedEntry, AdmissionError]:
    """Admit an entry from the octets that are its identity."""
    node = decode(octets)
    if isinstance(node, Err):
        return Err(AdmissionError(AdmissionFailure.NOT_CANONICAL, str(node.error)))
    read = decoded(lambda: read_entry(node.value))
    if isinstance(read, Err):
        return Err(AdmissionError(AdmissionFailure.NOT_A_TRANSCRIPT_ENTRY, str(read.error)))
    entry = read.value

    if encode(entry_node(entry)) != octets:
        return Err(AdmissionError(AdmissionFailure.RE_ENCODES_DIFFERENTLY, str(len(octets))))

    binding = _binding_of(entry)
    bound = _check_binding(scope.tenant_id, case_id, binding)
    if isinstance(bound, Err):
        return bound

    stored = scope.content.put(DigestKind.TRANSCRIPT_ENTRY, octets)
    if isinstance(stored, Err):
        return Err(_store_refused(stored.error))
    return Ok(AdmittedEntry(entry, stored.value))


def admit_case_construction(
    scope: TenantScope, case_id: str, record: CaseConstructionRecord
) -> Result[Digest, AdmissionError]:
    """Admit the record that opens a case, under the same binding rule.

    **Every party is checked, not only the record.**  A construction record
    carries the parties and their roles -- roles come from here, signed by an
    officer, and never from a party's own assertion about itself -- and each
    party names a tenant of its own.  Checking the outer binding alone would
    let a case in one tenant permanently hold an authored role declaration for
    another tenant's principal, under a digest that looks entirely valid.  The
    store is keyed by tenant, so nothing could *read* it across the boundary;
    what it would corrupt is the tenant's own authored state, and there is no
    operation that deletes a stored preimage.
    """
    bound = _check_binding(scope.tenant_id, case_id, (record.tenant_id, record.case_id))
    if isinstance(bound, Err):
        return bound
    for party in record.parties:
        if party.tenant_id != scope.tenant_id:
            return Err(
                AdmissionError(
                    AdmissionFailure.TENANT_MISMATCH,
                    f"party {party.principal_id!r} names {party.tenant_id!r} "
                    f"in a case under {scope.tenant_id!r}",
                )
            )
    stored = scope.content.put(DigestKind.CASE_CONSTRUCTION, encode(record.to_node()))
    if isinstance(stored, Err):
        return Err(_store_refused(stored.error))
    return Ok(stored.value)


def _binding_of(entry: TranscriptEntry) -> tuple[str, str]:
    match entry:
        case Attestation(receipt):
            return receipt.payload.tenant_id, receipt.payload.case_id
        case Statement(record):
            return record.tenant_id, record.case_id


def _check_binding(
    tenant_id: str, case_id: str, binding: tuple[str, str]
) -> Result[None, AdmissionError]:
    carried_tenant, carried_case = binding
    if carried_tenant != tenant_id:
        return Err(
            AdmissionError(
                AdmissionFailure.TENANT_MISMATCH, f"{carried_tenant!r} into {tenant_id!r}"
            )
        )
    if carried_case != case_id:
        return Err(
            AdmissionError(AdmissionFailure.CASE_MISMATCH, f"{carried_case!r} into {case_id!r}")
        )
    return Ok(None)


def _store_refused(error: StoreError) -> AdmissionError:
    return AdmissionError(
        AdmissionFailure.STORE_REFUSED, f"{error.failure.value} {error.digest} {error.detail}"
    )
