"""Core domain values: the canonical wire, the value algebra, the expression IR,
the case record, and the analysis record.

``muster.core`` imports nothing else from ``muster``. Everything else depends on
it, so a dependency that leaks into here reverses the whole graph.
"""
