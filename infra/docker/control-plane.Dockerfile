#  The control-plane image.  One process, two Python distributions, and
#  deliberately not the third.
#
#  ``muster-agents`` is absent, and its absence is the whole reason this is a
#  second image rather than a second entrypoint on the first.  An agent runtime
#  brings a model client and an agent framework; installed here they would sit
#  in the process that holds the case salt, the transcript and the database
#  connection, and "the control plane has no model dependency" would stop being
#  checkable with ``pip list``.  There is no ADK here, no ``google-genai``, no
#  storage client and no way for one to arrive without a diff to this file.
#
#  What it does carry beyond the two distributions is the *worked case*: the
#  fixture the suite runs and the composition root that drives it.  A demo with
#  its own seed would be a second definition of the case and the first thing to
#  drift, so the seed shipped here is the one every commit is checked against.
#  Nothing else from the test tree comes with it -- not a suite, not a conftest,
#  not the agents' source material, which belongs to the sources and is read by
#  them out of their own bucket.

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

COPY packages/muster-platform/pyproject.toml /build/packages/muster-platform/pyproject.toml
COPY packages/muster-platform/src /build/packages/muster-platform/src
RUN pip install --prefix=/install --find-links=/wheels ./packages/muster-platform


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system muster \
 && useradd --system --gid muster --home-dir /home/muster --create-home muster

COPY --from=build /install /usr/local

#  The layout matters: ``support.paths`` finds the case fixture by walking up
#  from its own file, so the two have to sit at the same relative depth they do
#  in the repository.  The composition root does the same walk to put the
#  fixture package on its path.  Copying them anywhere else would work until
#  somebody moved one.
WORKDIR /app
COPY demo/cloud_hero.py /app/demo/cloud_hero.py
COPY packages/muster-platform/tests/support /app/packages/muster-platform/tests/support
COPY packages/muster-kernel/fixtures /app/packages/muster-kernel/fixtures

USER muster

#  A job, so there is no port and nothing listening.  The entrypoint runs once,
#  reports, and exits non-zero if the case did not reach the invariant answer.
ENTRYPOINT ["python", "/app/demo/cloud_hero.py"]
