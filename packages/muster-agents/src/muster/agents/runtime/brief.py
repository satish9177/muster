"""The brief: a source-local question, and nothing that could be read as a case.

What a model is asked here is deliberately small and deliberately dull.  For
each labelled target it is asked what **this source's own material directly
shows** -- and it is told, in the same breath, that declining is a correct
answer and that inferring is not.

What it is never asked, and has no vocabulary to answer:

* whether the evidence is *sufficient* -- that is the planner's question, over
  a logical case this agent has never seen;
* whether anybody should be *paid* -- that is a policy entailment, computed by
  a solver from a signed bundle, and no source has standing to state one;
* what MUSTER should *decide* -- there is no such tool, no such field and no
  such sentence in the brief.

Nothing about the case travels into the brief either.  Not the parties, not the
other propositions, not what has already been established, and not what this
answer would change.  A model that knew its answer settled the case would have
a reason to prefer one answer, and the cheapest way to guarantee it does not
know is to not tell it.

The type instructions are generated from the *pinned* sort and domain, so a
bundle that adds a predicate adds a line of prose and no code.  They are strict
about spelling because the parser on the other side is strict about spelling:
telling a model "a whole number of minutes between 0 and 1440" and then
accepting ``1_440`` would be advertising a contract the validator does not
honour.
"""

from __future__ import annotations

from muster.agents.runtime.observations import label_for
from muster.core.evidence.acquisition import AcquisitionAssignment, AcquisitionTargetSpec
from muster.core.values.sorts import (
    BoolDomain,
    BoolSort,
    Domain,
    EnumDomain,
    EnumSort,
    IntRange,
    IntSort,
    ScaledRange,
    ScaledSort,
    Sort,
)

#: The rules every profile's interpreter works under.  Written as constraints
#: on the answer rather than as encouragement, because an instruction a model
#: can satisfy by trying harder is not a boundary.
STANDING_RULES = """\
You interpret evidence held by one source. You do not decide anything.

Rules, in order of precedence:

1. Answer only from the local evidence available to you through your tools and
   from the media attached to this conversation. You have no other knowledge of
   this matter and must not supply any.
2. Record an observation only when the local evidence *directly shows* it. Do
   not infer, estimate, reconstruct, or fill a gap with what is likely.
3. If the evidence does not directly show a target, do not record it. Decline
   instead, naming the reason. Declining is a correct and expected answer, and
   it is always better than an unsupported observation.
4. If the evidence is ambiguous, contradicts itself, does not identify the named
   subject, or cannot be read, decline with that reason.
5. Record at most one observation per target.
6. State no conclusion about the matter this evidence is being collected for.
   You do not know what it decides, and it is not yours to say.
"""


def compose_instruction(assignment: AcquisitionAssignment, *, source_class: str) -> str:
    """The complete instruction for one assignment.

    ``source_class`` is stated to the model as *what it is speaking as*, and it
    is configuration rather than a choice: nothing the model can produce sets
    it, and nothing it says about it is read back.  It is in the brief because
    an interpreter that knows it is a badge-access system reads a badge log
    better, not because it has any say in the matter.
    """
    lines = [
        STANDING_RULES,
        "",
        f"You are the local interpreter for a {source_class} source.",
        "",
        "Targets you have been asked about:",
        "",
    ]
    for index, target in enumerate(assignment.targets):
        lines.append(_describe(label_for(index), target))
        lines.append("")
    lines.extend(
        [
            "Work through the targets one at a time.",
            "List the local evidence, read what you need, and then either record"
            " an observation for a target or decline.",
        ]
    )
    return "\n".join(lines)


def _describe(label: str, target: AcquisitionTargetSpec) -> str:
    """One target, as a question about material rather than about a case."""
    where = ", ".join(f"{scope.scope_kind} {scope.scope_value}" for scope in target.resource_scope)
    arguments = ", ".join(target.proposition.args)
    measurement = target.measurement_class or "local record"
    return (
        f"{label}. {target.proposition.predicate_id}({arguments})\n"
        f"   subject:   {target.subject}\n"
        f"   resource:  {where}\n"
        f"   evidence:  {measurement}\n"
        f"   question:  what does this source's own evidence directly show for"
        f" {target.proposition.predicate_id} of {arguments}?\n"
        f"   answer as: {_typing(target.value_sort, target.domain)}"
    )


def _typing(sort: Sort, domain: Domain) -> str:
    """How a value of this sort must be spelled, and which relations are open."""
    match sort, domain:
        case BoolSort(), BoolDomain():
            return "relation 'exact', value exactly 'true' or 'false'"
        case IntSort(), IntRange(lo, hi):
            return (
                f"relation 'exact', 'at_least' or 'at_most'; value a whole number "
                f"written in plain digits, between {lo} and {hi}. Prefer 'at_least' "
                f"when the evidence shows a floor rather than an exact figure"
            )
        case ScaledSort(unit_tag, scale), ScaledRange(lo, hi):
            return (
                f"relation 'exact', 'at_least' or 'at_most'; value an amount in {unit_tag} "
                f"with at most {scale} decimal places, between "
                f"{_amount(lo, scale)} and {_amount(hi, scale)}"
            )
        case EnumSort(), EnumDomain(members):
            return (
                f"relation 'exact' for one of {', '.join(members)}, or 'one_of' with a "
                f"comma-separated subset of them"
            )
        case _:
            #  A sort and domain the bundle validated as matching, in a pairing
            #  this renderer has not been taught.  Saying so is better than
            #  inventing a spelling rule the parser does not implement.
            return "relation 'exact'; this source cannot state how to spell this value"


def _amount(minor: int, scale: int) -> str:
    if scale == 0:
        return str(minor)
    negative = minor < 0
    digits = str(abs(minor)).rjust(scale + 1, "0")
    rendered = f"{digits[:-scale]}.{digits[-scale:]}"
    return f"-{rendered}" if negative else rendered
