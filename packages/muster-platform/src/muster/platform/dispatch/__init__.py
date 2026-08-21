"""Sending a request to the source that can answer it, and admitting the reply.

Three responsibilities, and the boundaries between them are the design:

* **assign** -- resolve one durable ``EvidenceRequest`` into one assignment per
  cataloged agent, using the pinned bundle for what a value must look like, the
  officer-signed construction record for where the case is, and the fleet
  catalog for which agent to address.  Pure over the artifacts it is handed;
* **transport** -- a protocol, and nothing here that implements it.  A source
  runs somewhere this package must not know about, so the edge is one method
  over octets, declared in the kernel's wire seam where both sides can see it.
  Two implementations exist and neither is here: one carries octets to an agent
  in the same interpreter and lives beside the agent runtime, the other carries
  them over an authenticated network call and lives in ``adapters.http`` --
  which is where a credential and a socket are allowed to be, and where an
  import contract keeps them;
* **acquire** -- drive the two, check the reply's envelope against what was
  asked, and hand each receipt to the ordinary ``AppendTranscriptEntry``
  command.

**Nothing here decides anything.**  Routing produces an address; an address is
not a permission.  Every receipt that comes back is verified and judged by
check Q-12 against the authority snapshot the *case* pinned, on exactly the
path a receipt delivered by any other means would take -- so deleting this
package would change which evidence arrives and would change no admission
decision.  That is why the reply is submitted through the public command rather
than through a shortcut this package could offer itself.

**And nothing here is a second door.**  There is no "trusted agent" flag, no
pre-validated path, and no way to spell "admit this because we asked for it".
The one thing an assignment establishes is that the case *solicited* a
proposition, and solicitation is a **narrowing**: it can only remove source
classes that the bundle would otherwise have allowed.
"""
