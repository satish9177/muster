"""The control plane's authority seam: publish grants, resolve pinned snapshots.

Two operations and a hard rule between them.

**Publication is a trusted control-plane act.**  A snapshot arrives here signed
by a publisher key, is verified against the trusted publisher keyring before it
is stored, and is stored under the digest of the snapshot it carries.  No agent
reaches this module: nothing an agent submits can add a grant, which is why
``SELF_DECLARED_CAPABILITY_DOES_NOT_GRANT_AUTHORITY`` is a statement about the
call graph and not about a filter.

**Resolution is by pin, never by recency.**  A case names the snapshot it is
decided against inside its authorization context, and this module resolves
*that* digest.  There is no "current snapshot" accessor here for a caller to
reach for by mistake -- publishing a successor does not change any answer any
existing case gives, and the only way to decide a case under a newer snapshot
is to open a revision that pins it.

This module knows nothing about the fleet catalog and must never import it.  An
import contract enforces it: an authority decision that could consult a catalog
would be an authority decision an agent could influence.
"""
