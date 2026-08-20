"""The control plane's fleet seam: publish agent profiles, route to one.

Separate from :mod:`muster.platform.authority` on purpose, and the separation
is enforced by an import contract rather than by convention: **the authority
module may not import this one.**  If it could, an authority decision would
have a path to catalog data, and catalog data is the one thing in this system
whose whole job is to describe agents.

What this seam offers is deliberately small:

* **publish** a signed catalog snapshot -- a control-plane act, never an agent
  self-registration;
* **route** a request: which cataloged agent is a *candidate* to acquire this
  predicate over this resource in this tenant.

What it does not offer, at all, is any function whose result an admission
decision reads.  A route is an address.  The attestation that comes back is
judged by Q-12 against the pinned authority snapshot, and would be judged
identically if the address had been typed in by hand.
"""
