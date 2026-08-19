"""Turning one committed record into the several views it is allowed to become.

``commit`` decided what is bound.  This package decides what is *shown*, and it
decides it from two inputs only: the pinned disclosure policy, and an audience
class that the caller did not choose.  Nothing here branches on a role; the
policy is a table and this is its interpreter.

The reader-side check lives here too, and that placement is the point.  A view
is verified against the same policy and the same rules that produced it, by
code a participant can run without holding anything secret -- so "MUSTER
redacted this correctly" is something the recipient establishes rather than
something they are told.
"""
