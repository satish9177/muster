"""A small, high-value evaluation set for source-local interpretation.

Not a benchmark.  Eight cases, chosen because each one is a *different way to be
wrong*, and each has one correct answer that is either a specific narrow
observation or an abstention naming a specific reason:

    clearly present, a full day         presence, and a lower bound
    present, under the threshold        presence, and an upper bound below it
    clearly absent                      presence = false
    somebody else was there             abstain: subject not identified
    an entry with no exit               presence only; no duration is supported
    the records contradict each other   abstain: contradictory
    the export is not readable text     abstain: unreadable
    nothing held about this subject     abstain: no evidence

**Half of them are abstentions, and that ratio is the point.**  An interpreter
that always answers is worse than one that answers four times out of eight and
declines the rest, because four of these have no answer the material supports.

Two cases are deliberately *not* here, because they are refused before a model
is ever invoked and belong with the boundary regressions rather than with an
evaluation of reading: an assignment about a site this agent does not serve, and
an assignment for a predicate it does not acquire.

What runs here by default is the deterministic interpreter, and what that
measures is the **plumbing**: that a given reading produces the receipt or the
abstention the case expects, end to end, through the real agent.  The same cases
run against a live model when one is configured, and that measures the
**model**.  One set of expectations, two subjects.
"""
