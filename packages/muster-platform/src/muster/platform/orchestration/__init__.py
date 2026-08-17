"""Pure orchestration: which imperative step happens next, and nothing more.

Every module here is a total function of values.  Nothing reads a clock, a
connection or an environment -- ``now`` arrives as an argument because it
changes the answer, and everything else that could is refused entry, which is
the same rule the kernel applies to ``as_of``.

The boundary this package must not cross is the one that makes the whole design
work: the orchestrator decides *what to do next*, never *what is true*.  It does
not decide whether policy entails something, whether an action is invariant,
what evidence is logically sufficient, or whether anything may be settled.  It
reads answers the kernel already gave and picks the next step.
"""
