"""The SMT adapter.

This subtree is the only place in the production tree that imports ``z3``.
Nothing above it names a solver library type, and the kernel keeps depending on
:class:`muster.solve.backend.SolverBackend` rather than on anything here.
"""
