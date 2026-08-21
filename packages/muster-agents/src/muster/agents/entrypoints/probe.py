"""Try to read one private site object, under whatever identity is running this.

The isolation claim has an observable, and this is it.  Run under the site
agent's service identity, this reads the object.  Run under the control plane's
service identity, this receives a real permission denial from Cloud Storage --
because the control plane holds no grant on that bucket, not because MUSTER
withheld anything.

    muster-agent-probe gs://bucket/prefix manifest.json

It prints one line and exits with a code that says which happened, so a
deployment check can assert on it and a demo can show it without a screenshot
anybody has to take on trust:

    0   readable      the identity running this can read the object
    3   denied        the storage layer refused it: this is the evidence
    4   absent        the object is not there
    5   unavailable   the store could not be reached at all

**Nothing here fakes anything.**  There is no flag that simulates a denial, no
mode that prints one without calling, and no branch that decides what to print
from configuration.  The line comes from whatever the storage layer answered.

**And nothing here prints the material.**  Success reports the octet count.  A
probe that dumped a private object to a terminal would be a probe that defeats
the boundary it exists to demonstrate, and it would do it in the one place
somebody is definitely watching.
"""

from __future__ import annotations

import sys

from muster.agents.sources.ports import EvidenceStoreError, EvidenceStoreFailure
from muster.core.results import Err

GCS_SCHEME = "gs://"

READABLE = 0
USAGE = 2
DENIED = 3
ABSENT = 4
UNAVAILABLE = 5

_CODES: dict[EvidenceStoreFailure, int] = {
    EvidenceStoreFailure.ACCESS_DENIED: DENIED,
    EvidenceStoreFailure.NOT_FOUND: ABSENT,
    EvidenceStoreFailure.UNREADABLE: UNAVAILABLE,
    EvidenceStoreFailure.STORE_UNAVAILABLE: UNAVAILABLE,
}


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or not arguments[0].startswith(GCS_SCHEME):
        print(f"usage: muster-agent-probe {GCS_SCHEME}BUCKET[/PREFIX] OBJECT", file=sys.stderr)
        return USAGE
    bucket, _, prefix = arguments[0][len(GCS_SCHEME) :].partition("/")
    name = arguments[1]

    from muster.agents.google.storage import GcsEvidenceStore  # noqa: PLC0415

    store = GcsEvidenceStore(bucket=bucket, prefix=prefix)
    #  The object accessor deliberately, rather than ``read``: a probe asks
    #  the *storage layer* whether this identity may have these octets, and
    #  going through the manifest first would report a manifest denial when
    #  the interesting answer is about the object.
    octets = store.read_object(name)
    if isinstance(octets, Err):
        return _report(bucket, prefix, name, octets.error)
    print(f"READABLE {GCS_SCHEME}{bucket}/{_path(prefix, name)} {len(octets.value)} octets")
    return READABLE


def _report(bucket: str, prefix: str, name: str, error: EvidenceStoreError) -> int:
    label = {
        EvidenceStoreFailure.ACCESS_DENIED: "DENIED",
        EvidenceStoreFailure.NOT_FOUND: "ABSENT",
    }.get(error.failure, "UNAVAILABLE")
    print(f"{label} {GCS_SCHEME}{bucket}/{_path(prefix, name)} {error.detail}", file=sys.stderr)
    return _CODES[error.failure]


def _path(prefix: str, name: str) -> str:
    return f"{prefix.rstrip('/')}/{name}" if prefix else name


if __name__ == "__main__":
    raise SystemExit(main())
