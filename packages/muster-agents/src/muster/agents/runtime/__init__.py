"""The acquisition runtime: brief, interpret, validate, bind, sign.

One pipeline, shared by all three profiles, and every stage narrows:

    assignment
      -> the agent's own scope and capability check      (refuse before asking)
      -> a brief naming labelled targets and nothing else
      -> an ADK agent whose only way to answer is a typed, closed tool
      -> deterministic validation against the pinned sort and domain
      -> the assignment's own target whitelist
      -> a payload bound to tenant, case, request, schema and instant
      -> a signature applied by code the model cannot call

Nothing widens.  There is no stage at which a model can name a proposition the
assignment did not, choose a source class, reach a resource this agent does not
serve, or cause a signature.  Those are not policies enforced by a check that
could be forgotten; they are the absence of an argument.
"""
