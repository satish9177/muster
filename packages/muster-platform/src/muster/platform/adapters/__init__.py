"""The only place a driver or an external service appears.

Two implementations of the custody protocols live here and they are peers:
``sql`` over PostgreSQL, which is what production means, and ``memory``, which
is what a unit test means.  Neither is a fallback for the other -- ``memory``
holds no lock and proves nothing about concurrency, and ``sql`` is too slow to
be the substrate of a decision-logic test -- and a shared contract suite runs
against both so that the two cannot drift into two semantics.

No clock.  Every operation above takes the reading it decides under as an
argument, so there is nothing here for a clock to serve.
"""
