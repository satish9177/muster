"""Committing a decision record: salts, the commitment tree, the envelope.

This package turns a *published* revision and its certificate into an
authenticated commitment that a participant can be handed a redacted slice of.
It decides nothing.  Everything it reads was already decided by the kernel and
already made durable by ``casework``; what it adds is the ability to prove, to
somebody who holds only part of the record, that the part they hold came from
the whole.

The split from ``disclose`` is the one that matters: **this package knows what
was committed and nothing about who may see it.**  A commitment binds every
leaf whether or not anybody will ever be shown it, which is precisely what
makes one audience's view checkable against another's.
"""
