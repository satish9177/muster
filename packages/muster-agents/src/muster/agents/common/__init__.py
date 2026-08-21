"""What every profile needs and no profile decides: identity, clock, entropy.

Each of the three is a port with two implementations -- an ambient one for a
deployed agent and an injected one for a test -- and each is a port for the
same reason the control plane takes ``now`` as an argument rather than reading
it: a value that arrives from the environment is a value no test can pin, and
an acquisition that cannot be reproduced cannot be attacked.
"""
