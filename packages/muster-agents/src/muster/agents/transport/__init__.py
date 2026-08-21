"""Carrying assignment octets to an agent, in process or over the network.

Two implementations of one shared port, and the difference between them is
custody rather than semantics.  The in-process one hands the octets to an agent
object in the same interpreter; the deployed one hands them to a service the
source operates, behind that service's own identity.  Both encode, both decode,
both refuse the same way -- so a case that acquires evidence locally exercises
the same envelope checks it would in the cloud, and a bug that only appears
over the network is a bug about the network.
"""
