"""Composition roots: the only modules that read the environment and build things.

Everything else in this distribution takes what it needs as an argument.  These
two read configuration, construct one agent, and hand it to a server or to a
probe -- which is why they are the only place a store, a model, a signer or an
identity checker is *chosen* rather than injected.
"""
