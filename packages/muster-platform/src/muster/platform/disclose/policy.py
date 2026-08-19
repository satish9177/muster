"""The disclosure policy, validated once and then read as a table.

A disclosure decision is a total function of three things and nothing else:

    (outcome class, action kind, audience class, disclosure context)  ->  entry
    entry.permitted_paths                                             ->  what is shown

There is no rule in this module about workers, employers, sites or auditors,
and there must never be one: the moment a role appears in a branch here, the
policy stops being the authority and the bundle's signature stops meaning what
it says.  What is here instead is the *interpreter* -- the lookup, and the
validations that make the lookup safe to trust.

**A missing entry is a refusal, not a default.**  Falling back to "disclose
nothing" would be the safe-looking choice and it is the wrong one: it makes an
operator's omission indistinguishable from a deliberate empty disclosure, and
the resulting empty views look like a working system.

**Validation happens when the policy is pinned, not when a view is built.**  A
policy naming a path outside the frozen inventory could over-disclose, and a
policy with two entries under one key has no deterministic answer at all.
Refusing at pin time means such a policy never reaches the point of producing
a view; refusing at build time would mean it produced correct views right up
until the first case that hit the bad entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from muster.core.analysis.outcomes import AnalysisOutcome, Invariant, outcome_class
from muster.core.results import Err, Ok, Result
from muster.core.wire.digests import Digest, DigestKind, digest_node
from muster.platform.commit.paths import path_in_inventory
from muster.policy.artifacts import DisclosureEntry, DisclosurePolicy, RatificationSet

#: ``action_kind`` is ``Some`` exactly for an invariant outcome, and the
#: enumeration below is what makes that statement checkable.  ``Divergent``
#: reaches a *set* of actions, and ``Infeasible`` and ``Indeterminate`` reach
#: none at all, so keying on an action kind alone has no total selection
#: function -- which is why the key is four-part and this is one of the four.
OUTCOME_CLASSES = frozenset({"INVARIANT", "DIVERGENT", "INFEASIBLE", "INDETERMINATE"})


class PolicyFailure(Enum):
    #: Two entries share the four-part key.  Never resolved by order or by
    #: recency: both are equally authoritative and picking one is a decision
    #: nobody ratified.
    ENTRY_CONFLICT = "ENTRY_CONFLICT"
    #: No entry for this key.  A refusal, not an empty disclosure.
    ENTRY_MISSING = "ENTRY_MISSING"
    #: An entry names a path the frozen inventory cannot produce.
    UNKNOWN_COMMITMENT_PATH = "UNKNOWN_COMMITMENT_PATH"
    #: ``action_kind`` is present on a non-invariant entry, or absent from an
    #: invariant one.  Either way the entry can never be selected, which is a
    #: policy that silently discloses nothing rather than one that is wrong.
    ACTION_KIND_MISMATCH = "ACTION_KIND_MISMATCH"
    #: The entry says a disclosure reveals a sensitive input by inference, and
    #: does not name a ratification that resolves inside the pinned bundle.
    UNACKNOWLEDGED_INFERENCE = "UNACKNOWLEDGED_INFERENCE"
    #: An outcome class outside the closed set.
    UNKNOWN_OUTCOME_CLASS = "UNKNOWN_OUTCOME_CLASS"
    #: Two rows for one audience and context permit different paths, and
    #: neither lets that audience see the outcome tag -- so a reader cannot
    #: tell which row governs the record they were shown, and a writer picks
    #: whichever permits least.  Refused when the policy is pinned, because
    #: there is no reader-side check that can recover from it.
    ROW_SET_NOT_READER_DECIDABLE = "ROW_SET_NOT_READER_DECIDABLE"


@dataclass(frozen=True, slots=True)
class PolicyError:
    failure: PolicyFailure
    detail: str


def entry_digest(entry: DisclosureEntry) -> Digest:
    """The identity a view names, so a reader can find the exact entry applied."""
    return digest_node(DigestKind.DISCLOSURE_ENTRY, entry.to_node())


def action_kind_of(outcome: AnalysisOutcome) -> str | None:
    """The action kind an outcome names, which is one exactly when it is invariant."""
    return outcome.action.kind if isinstance(outcome, Invariant) else None


def _key(entry: DisclosureEntry) -> tuple[str, str | None, str, str]:
    return (
        entry.outcome_class,
        entry.action_kind,
        entry.audience_class,
        entry.disclosure_context,
    )


def validate_policy(
    policy: DisclosurePolicy, *, ratifications: RatificationSet
) -> Result[None, PolicyError]:
    """Everything that has to be true before this policy may decide anything."""
    seen: dict[tuple[str, str | None, str, str], int] = {}
    for index, entry in enumerate(policy.entries):
        if entry.outcome_class not in OUTCOME_CLASSES:
            return Err(
                PolicyError(
                    PolicyFailure.UNKNOWN_OUTCOME_CLASS,
                    f"entry {index}: {entry.outcome_class!r}",
                )
            )
        key = _key(entry)
        if key in seen:
            return Err(
                PolicyError(
                    PolicyFailure.ENTRY_CONFLICT,
                    f"entries {seen[key]} and {index} share the key {key}",
                )
            )
        seen[key] = index

        if (entry.outcome_class == "INVARIANT") != (entry.action_kind is not None):
            return Err(
                PolicyError(
                    PolicyFailure.ACTION_KIND_MISMATCH,
                    f"entry {index}: action_kind is present iff outcome_class is INVARIANT",
                )
            )

        for path in entry.permitted_paths:
            if not path_in_inventory(path):
                return Err(
                    PolicyError(
                        PolicyFailure.UNKNOWN_COMMITMENT_PATH, f"entry {index} permits {path!r}"
                    )
                )

        if entry.reveals_sensitive_input:
            reference = entry.inference_acknowledgement_ref
            if reference is None or ratifications.record(reference) is None:
                return Err(
                    PolicyError(
                        PolicyFailure.UNACKNOWLEDGED_INFERENCE,
                        f"entry {index} discloses by inference without a resolvable "
                        f"acknowledgement in the pinned bundle",
                    )
                )

    conflict = _undecidable_row_set(policy)
    if conflict is not None:
        return Err(conflict)
    return Ok(None)


#: The leaf whose disclosure lets a reader decide which of an audience's rows
#: governs the record it was shown.
OUTCOME_TAG = "kernel.outcome.tag"


def _undecidable_row_set(policy: DisclosurePolicy) -> PolicyError | None:
    """Can a reader tell which of an audience's rows applies to what it holds?

    The permitted set, the required set and the inference notice are all read
    off the entry a view *names*, so an entry a reader cannot tie back to the
    record is an entry the writer chose.  The reader-side check ties them
    together through the outcome tag -- but only when the audience is shown it.

    Where an audience is not shown the tag, its rows must therefore be
    indistinguishable in what they permit: then choosing among them changes
    nothing, and the writer's freedom is worth nothing.  Where they differ,
    the writer picks whichever permits least and under-discloses inside a view
    that verifies, and no reader-side check can catch it.  So the policy is
    refused rather than the view.
    """
    by_audience: dict[tuple[str, str], list[DisclosureEntry]] = {}
    for entry in policy.entries:
        by_audience.setdefault((entry.audience_class, entry.disclosure_context), []).append(entry)

    for (audience, context), rows in by_audience.items():
        if len(rows) < 2 or any(OUTCOME_TAG in row.permitted_paths for row in rows):
            continue
        permitted = {frozenset(row.permitted_paths) for row in rows}
        if len(permitted) > 1:
            return PolicyError(
                PolicyFailure.ROW_SET_NOT_READER_DECIDABLE,
                f"({audience}, {context}) has rows permitting different paths and none "
                f"disclosing {OUTCOME_TAG}, so no reader can tell which one governs a view",
            )
    return None


def resolve_entry(
    policy: DisclosurePolicy,
    *,
    outcome: AnalysisOutcome,
    audience_class: str,
    disclosure_context: str,
) -> Result[DisclosureEntry, PolicyError]:
    """The one entry that governs this disclosure, or a typed refusal.

    The outcome is passed rather than its class so that the action kind is read
    off the same value: an entry selected under one outcome's class and another
    outcome's action kind is a row nobody wrote.
    """
    want = (outcome_class(outcome), action_kind_of(outcome), audience_class, disclosure_context)
    matches = [entry for entry in policy.entries if _key(entry) == want]
    if not matches:
        return Err(PolicyError(PolicyFailure.ENTRY_MISSING, f"no entry for {want}"))
    if len(matches) > 1:
        #  ``validate_policy`` refuses this, so reaching it means a policy was
        #  applied without being pinned.  Refused again rather than trusted.
        return Err(PolicyError(PolicyFailure.ENTRY_CONFLICT, f"{len(matches)} entries for {want}"))
    return Ok(matches[0])


def find_entry_by_digest(
    policy: DisclosurePolicy, digest: Digest
) -> Result[DisclosureEntry, PolicyError]:
    """The entry a view names, resolved inside the policy the reader supplied.

    This is the reader's half of the lookup and it runs against *their* policy,
    not the writer's: an entry that resolves in one and not the other is a
    policy substitution, and it is detected here rather than assumed away.
    """
    matches = [entry for entry in policy.entries if entry_digest(entry) == digest]
    if len(matches) != 1:
        return Err(
            PolicyError(
                PolicyFailure.ENTRY_MISSING,
                f"the named entry resolves to {len(matches)} entries in the pinned policy",
            )
        )
    return Ok(matches[0])
