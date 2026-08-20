"""Source authority: which key may say which thing, where, when, for whom.

A signature answers *"which key signed these bytes"*.  Authority answers *"was
that key allowed to assert this proposition, for this resource, in this tenant,
under this policy version, at this moment".*  They are different questions with
different answers, and this package exists so that no reader can confuse them:
nothing here verifies a signature, and nothing that verifies a signature grants
authority.
"""
