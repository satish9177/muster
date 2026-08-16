"""The composition layer: rebuild, analyse, plan, assemble, and the local CLI.

The only module permitted to see every other one, because assembling a
certificate needs the kernel record and the planning record together and neither
may depend on the other.
"""
