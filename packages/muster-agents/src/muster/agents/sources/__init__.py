"""Where an agent's own material lives, and the one shape it is read through.

A source store is the only thing in this distribution that touches raw private
evidence.  Everything above it works on *handles* -- an identifier, a media
type, a short label -- and the octets appear in exactly one place: the content
handed to the interpreter by the source's own process, which carries it to the
configured model endpoint.

The port has two implementations and they differ in one respect that matters
operationally and in none that matters semantically: a directory on disk is
what a site runs in development, and a private Cloud Storage bucket is what it
runs deployed.  In both, the identity that can read the material is the
source's own, and the control plane's is not -- which is a fact about an IAM
policy in one and about a filesystem in the other, and is asserted rather than
assumed in both.
"""
