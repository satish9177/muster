#  The agent image.  One process, two Python distributions, and deliberately
#  not the third.
#
#  ``muster-platform`` is absent, and its absence is a fact about the image
#  rather than a rule somebody has to remember: a container that cannot import
#  the control plane cannot reach a case salt, a transcript or a database, and
#  "an agent has no database access of any kind" is checkable with `pip list`.
#
#  Nothing but source is copied.  No fixtures -- the deployed site reads its
#  material from a private bucket, and an image carrying a copy would be a
#  second, unversioned holding of it.  No tests, no spec, no demo, no docs.

FROM python:3.12-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

#  The kernel first: it has no dependencies, so it is the layer that changes
#  least and the one worth caching on its own.
#
#  **The kernel is built into a wheel rather than installed on its own**, and
#  the reason is the defect this shape had until it was built: ``pip install
#  --prefix=/install`` puts a distribution somewhere pip does not look when it
#  resolves the *next* install, so the second command went to PyPI for
#  ``muster-kernel==0.1.0``, found nothing, and the build stopped.  A local
#  wheel on ``--find-links`` is a candidate pip does consider, and it keeps the
#  two layers separate -- which is what the split was for.
COPY packages/muster-kernel /build/packages/muster-kernel
RUN pip wheel --no-deps --wheel-dir=/wheels ./packages/muster-kernel

COPY packages/muster-agents/pyproject.toml /build/packages/muster-agents/pyproject.toml
COPY packages/muster-agents/src /build/packages/muster-agents/src
RUN pip install --prefix=/install --find-links=/wheels "./packages/muster-agents[cloud]"


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

#  A named, unprivileged account rather than a bare uid: a process that reads
#  private material should be legible in a process list, and the mount point
#  for its signing key has to be owned by somebody.
RUN groupadd --system muster \
 && useradd --system --gid muster --home-dir /home/muster --create-home muster \
 && mkdir -p /var/run/muster \
 && chown muster:muster /var/run/muster

COPY --from=build /install /usr/local

USER muster
WORKDIR /home/muster

EXPOSE 8080

#  The console script, not a module path: the entry point is part of the
#  distribution's own contract, so a rename is caught at build time rather than
#  at the first request.
ENTRYPOINT ["muster-agent"]
