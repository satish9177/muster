"""Who an agent is, stated once, in configuration a model cannot reach.

Three facts decide everything an agent is allowed to emit, and none of them is
ever an argument a model supplies:

* ``source_class`` -- the institution this agent speaks as.  It is
  *configuration*, not output.  A model that could name a class could name a
  different one, and the whole of "a shared source class is not a shared
  authority" would rest on a string a language model chose;
* ``principal_id`` -- the source instance the authority registry expects to
  hold this key.  The control plane checks it as Q-12(d); the agent carries it
  so an operator can see the two agree;
* ``resource_scope`` -- what this agent actually serves.  An assignment naming
  a coordinate outside it is refused *before* the model is invoked and before
  a signature is spent, which is the difference between a fleet-routing fault
  and a wasted attestation.

The key reference is here too, and the private key is not.  What signs is a
``SourceSigner``, which the composition root supplies; this record names the
identity that signer must present, so a payload cannot be built naming one key
and signed with another.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.authority.scope import ResourceScope
from muster.core.results import InvariantViolation


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """The institutional identity one agent speaks as.

    ``acquirable_predicates`` mirrors the cataloged profile: it is what the
    agent declares it can be asked for, and it is the *first* whitelist an
    assignment is checked against.  It is not authority -- the grant is in the
    registry and this record cannot create one -- but a predicate absent here
    is one this agent refuses to attempt, which keeps a mis-routed assignment
    from reaching a model at all.
    """

    agent_id: str
    principal_id: str
    tenant_id: str
    source_class: str
    key_ref: str
    acquirable_predicates: tuple[str, ...]
    resource_scope: tuple[ResourceScope, ...]

    def __post_init__(self) -> None:
        for name, value in (
            ("agent_id", self.agent_id),
            ("principal_id", self.principal_id),
            ("tenant_id", self.tenant_id),
            ("source_class", self.source_class),
            ("key_ref", self.key_ref),
        ):
            if not value:
                raise InvariantViolation(f"a source identity names a {name}")
        if not self.acquirable_predicates:
            raise InvariantViolation(f"{self.agent_id} declares no acquirable predicate")
        if not self.resource_scope:
            #  An empty scope would be the "absence means everything" reading
            #  the authority registry refuses, arriving through the back door
            #  of an agent's own configuration.
            raise InvariantViolation(f"{self.agent_id} declares no resource scope")

    def serves(self, coordinates: tuple[ResourceScope, ...]) -> bool:
        """Does this agent serve every coordinate an assignment names?

        Set containment over whole ``(kind, value)`` pairs, never a prefix
        rule: ``SITE-1`` is a prefix of ``SITE-10``, and a containment rule
        would hand the holder of one an authority over the other that nobody
        wrote down.
        """
        return set(coordinates) <= set(self.resource_scope)

    def may_be_asked_for(self, predicate_id: str) -> bool:
        return predicate_id in self.acquirable_predicates
