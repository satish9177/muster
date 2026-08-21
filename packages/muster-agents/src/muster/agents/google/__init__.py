"""The Google-specific edges of an agent: the model it calls, the bucket it reads.

Everything in this package is an adapter, and everything above it is written
against a port.  That is not tidiness -- it is the reason the deterministic
suite can run the *real* agent runtime with no network at all, and the reason
the same agent code serves a directory on a laptop and a private bucket in a
project the control plane has no grant on.

Two edges, and each one is where a real Google boundary sits:

* **the model** -- an ADK ``Gemini`` over Vertex AI or the Gemini API,
  configured by identifier rather than named in code, so upgrading a model is a
  deployment change and not a diff;
* **the object store** -- private site material, read by the source's own
  service identity.  The central control plane holds no grant on it and gets a
  real permission denial if it tries, which is the one claim in this system
  that a screenshot cannot fake and an IAM policy has to actually make true.
"""
