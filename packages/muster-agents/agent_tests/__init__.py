"""The agent-fleet suite.

Three things are checked here and nowhere else: that the agents are real ADK
runtimes, that a model cannot reach past the deterministic gate in front of it,
and that the whole loop -- request, route, interpret, sign, admit, rebuild --
produces the invariant answer without a network call anywhere in it.

**No test in this package calls a hosted model.**  The interpreter is injected,
and the suite injects a scripted one: a real ``BaseLlm`` driven through the real
ADK ``Runner``, so what is exercised is the agent runtime rather than a stand-in
for it.  The one test that does call a live model is marked and skipped unless
an operator opts in.
"""
