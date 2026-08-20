"""The fleet catalog: which institutional agents exist and can be routed to.

The catalog and the authority registry answer two different questions and must
never be one object:

    authority registry   who is *allowed* to attest what?
    fleet catalog        which agent profiles *exist*, and where do I send a
                         request for predicate P over resource R?

A catalog entry grants nothing.  Discovery returns a candidate, and the
candidate's attestation is judged by Q-12 against the pinned authority snapshot
exactly as any other attestation is -- so publishing a profile that claims a
capability buys the publisher nothing at all.  The regression that says so is
named ``SELF_DECLARED_CAPABILITY_DOES_NOT_GRANT_AUTHORITY``.

The dependency runs one way and only one way.  This package imports the
coordinate type and the publisher signing vocabulary from
``muster.core.authority``; **no module under ``muster.core.authority`` imports
anything here.**  An import contract enforces that direction, so "a catalog
cannot influence an authority decision" is a fact about the module graph rather
than a promise in a docstring -- Q-12 has no parameter a profile could reach.
"""
