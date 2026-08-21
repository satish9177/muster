"""Source-local acquisition agents: interpret locally, attest narrowly, leave.

An agent is not a domain expert and not a decision maker.  It is an
evidence-acquisition runtime that receives an ``AcquisitionAssignment``, looks
at material only it can reach, and returns either signed receipts carrying one
proposition each or a typed abstention.  It does not know which proposition
settles a case, what the policy says, what anybody else claimed, or whether its
answer moves anything -- and every one of those absences is deliberate: an
agent that knew whether its answer settled the case would have a reason to
prefer one answer.

Four boundaries hold the design up.

**The model interprets and never decides.**  A model's output reaches the world
through one deterministic path -- a closed tool whose arguments are typed, a
validator that refuses anything the pinned schema does not describe, a
whitelist that refuses any proposition the assignment did not name, and a
signature applied afterwards by code the model cannot call.  There is no branch
in this package where a model response becomes a fact, and no confidence figure
anywhere that becomes a truth.

**Raw material stays where it was found.**  What leaves a source is an
acquisition relation over one declared proposition, plus provenance.  Not a
clip, not a transcript, not a summary, not the prompt, not the response.

**Signing is the source's, and Q-12 is somebody else's.**  An agent holds a key
and signs what it observed.  Whether that key was permitted to say it is
decided by the control plane against the authority snapshot the *case* pinned,
and the agent's own pre-checks exist only to avoid spending a signature on
something the registry will refuse.

**Three profiles, one runtime.**  The worker, employer and site agents differ in
identity, in what they may reach, and in what they may emit -- and share every
line of the acquisition runtime.  Adding a domain adds a signed bundle and a
catalog entry, and adds no code here.
"""
