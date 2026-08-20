"""The decision, with every identity masked out.

Shared by the kernel's milestone-E transition audit and by the control plane's
durable acceptance suite, because both need the same question answered and two
copies of it would be two definitions of "the same decision".

**Why an identity-blind comparison became necessary at milestone E.**  Until
now a transcript entry's octets were a function of what it said, so the same
case built twice produced the same digests and a frozen constant could stand
for "this decision".  Milestone E verifies source signatures, so the control
plane's fixtures sign for real -- and ECDSA is randomised, so the same payload
signed twice is two different receipts with two different digests.  That is
correct: a signature is not a function of the message, and a system that needed
it to be would be using a scheme with a worse property.  What it costs is the
cross-session digest constant, and what replaces it is this: a comparison of
what was *decided*, which no signature can move.

What is masked, and why each one is an identity rather than a decision:

* the receipt digest inside a ``C-ATT`` constraint label -- provenance.  That
  one constraint came from one receipt stays visible; *which* receipt does not;
* the solver handle an ``Invariant`` outcome cites -- a digest of the query,
  which contains the revision, which contains every pin.

What is **not** masked, deliberately: the action, the witness world, every
established value, every constraint formula, every recorded non-effect and the
unresolved set.  Those are the answer, and a comparison that masked any of them
would be a comparison that could not fail.
"""

from __future__ import annotations

import hashlib
import json
import re

from muster.application.pipeline import CaseAnalysis
from muster.core.analysis.outcomes import outcome_class, outcome_node
from muster.core.case.revision import CaseRevision
from muster.core.expr.terms import term_node
from muster.core.wire.codec import encode

_ATTESTED_LABEL = re.compile(r"^C-ATT-[0-9a-f]+")


def semantic_core(revision: CaseRevision, analysis: CaseAnalysis) -> str:
    """A digest of what this case decided, blind to how it was identified.

    Built from named fields rather than from the record's own encoding.
    Blinding an encoding means substituting octet strings and hoping each one
    lands where it was meant to; naming the fields means the thing being
    compared is stated, and a field added later is *absent* from the comparison
    rather than silently folded into it.  Extending this when the decision
    gains a component is a deliberate act with a diff, which is the point.
    """
    outcome = analysis.kernel.outcome
    payload = {
        "declared": sorted(str(ref) for ref in revision.declared),
        "established": sorted(
            (str(fact.ref), encode(fact.value.to_node()).hex()) for fact in revision.established
        ),
        "constraints": sorted(
            (_ATTESTED_LABEL.sub("C-ATT", item.label), encode(term_node(item.formula)).hex())
            for item in revision.constraints
        ),
        "non_effects": sorted(
            (item.rule_id, item.subject, item.reason) for item in revision.non_effects
        ),
        "outcome_class": str(outcome_class(outcome)),
        "outcome": _without_handles(outcome),
        "unresolved": sorted(str(ref) for ref in analysis.projected.unresolved()),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _without_handles(outcome: object) -> str:
    """The outcome's encoding with the solver handle it cites masked.

    An ``Invariant`` outcome carries ``invariance_query_digest``: a handle for
    reproducing the run, not a statement about the answer, so it moves whenever
    any identity does.  The action and the witness world are left exactly as
    they are -- those *are* the answer.
    """
    hexed = encode(outcome_node(outcome)).hex()  # type: ignore[arg-type]
    handle = getattr(outcome, "invariance_query_digest", None)
    if handle is None:
        return hexed
    masked = hexed.replace(handle.octets.hex(), "<handle>")
    assert masked != hexed, "the handle does not occur, so masking it is a no-op"
    return masked
