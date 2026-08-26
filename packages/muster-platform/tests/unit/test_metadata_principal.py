"""How a deployed control plane finds out what it is running as.

The one implementation of ``RuntimePrincipal``, and everything about it that
matters is what it does *not* do: it takes no argument, reads no environment
variable, holds no credential, and asks an endpoint whose answer depends on
where the request came from.  That is what makes the identity unforgeable by
anything the control plane talks to.

No socket is opened here.  The opener is replaced, exactly as the transport's
own suite replaces it, so what is under test is the request this module makes
and the answers it accepts.
"""

from __future__ import annotations

import inspect
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from io import BytesIO

import pytest

from muster.core.results import Err, Ok
from muster.platform.adapters.http import (
    MAX_PRINCIPAL_OCTETS,
    METADATA_EMAIL_URL,
    MetadataServerPrincipal,
)
from muster.platform.gate.cloud import CloudPrincipalFailure

PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"


class _Answer(BytesIO):
    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *_excinfo: object) -> None:
        self.close()


@dataclass
class _Recording:
    body: bytes = PRINCIPAL.encode("ascii")
    requests: list[urllib.request.Request] = field(default_factory=list)

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> _Answer:  # noqa: ARG002
        self.requests.append(request)
        return _Answer(self.body)


def _asking(monkeypatch: pytest.MonkeyPatch, opener: object) -> None:
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: opener)


def test_the_workloads_own_identity_is_read_from_the_metadata_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _Recording(body=f"{PRINCIPAL}\n".encode("ascii"))
    _asking(monkeypatch, opener)

    found = MetadataServerPrincipal().principal_id()

    assert isinstance(found, Ok), found
    assert found.value == PRINCIPAL
    (request,) = opener.requests
    assert request.full_url == METADATA_EMAIL_URL
    #  The header is what makes this endpoint unreachable by luring a process
    #  into fetching a URL: a browser-shaped request without it is refused.
    assert request.get_header("Metadata-flavor") == "Google"
    assert request.get_method() == "GET"


def test_the_endpoint_is_asked_for_an_identity_and_never_for_a_credential() -> None:
    """A sibling of the token endpoint, and deliberately the other one.

    ``.../default/token`` returns a bearer credential; ``.../default/email``
    returns an address.  This module wants the second, and asking for the first
    would put an OAuth token in the process that decides authorization.

    The exact path is asserted, not just its tail.  A URL whose *host* or early
    segments drifted would be a URL some other server could answer -- and the
    whole reason this identity cannot be forged is that only the instance
    metadata server can answer this one.
    """
    assert METADATA_EMAIL_URL == (
        "http://metadata.google.internal"
        "/computeMetadata/v1/instance/service-accounts/default/email"
    )
    assert "token" not in METADATA_EMAIL_URL


def test_the_observed_principal_has_no_environment_or_request_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The identity is observed.  There is nowhere else it could come from.

    Two halves.  First, behaviour: with the metadata server refusing, the
    answer is a refusal even when every plausible environment variable is set
    to a perfectly well-formed service-account address.  A fallback would turn
    this into an ``Ok`` and hand a deployment's own configuration the job of
    saying who is running.

    Second, shape: ``principal_id`` takes no argument beyond ``self``, so there
    is no request field, header or caller-supplied value it could read even if
    somebody wanted it to.
    """

    class _Unreachable:
        def open(self, request: object, timeout: float | None = None) -> None:  # noqa: ARG002
            raise urllib.error.URLError("no metadata server")

    for name in (
        "MUSTER_PRINCIPAL",
        "MUSTER_HERO_GATE_PRINCIPAL",
        "GOOGLE_SERVICE_ACCOUNT",
        "SERVICE_ACCOUNT_EMAIL",
        "CLOUD_RUN_SERVICE_ACCOUNT",
        "K_SERVICE_ACCOUNT",
    ):
        monkeypatch.setenv(name, PRINCIPAL)
    _asking(monkeypatch, _Unreachable())

    refused = MetadataServerPrincipal().principal_id()

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE
    assert PRINCIPAL not in refused.error.detail

    signature = inspect.signature(MetadataServerPrincipal.principal_id)
    assert list(signature.parameters) == ["self"]


def test_the_metadata_flavor_header_is_what_the_request_carries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One header, spelled exactly, and no credential alongside it.

    ``Metadata-Flavor: Google`` is what makes the endpoint unreachable by
    luring some other process into fetching a URL: a browser-shaped request
    without it is refused by the metadata server itself.  What is asserted here
    is that this is the *only* header -- an Authorization header on this
    request would mean the process that decides authorization is carrying a
    credential it has no use for.
    """
    opener = _Recording()
    _asking(monkeypatch, opener)

    found = MetadataServerPrincipal().principal_id()

    assert isinstance(found, Ok), found
    (request,) = opener.requests
    assert request.get_header("Metadata-flavor") == "Google"
    assert set(request.headers) == {"Metadata-flavor"}
    assert request.data is None


def test_an_unreachable_metadata_server_is_a_value_and_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """"This process has no cloud identity" is a configuration fact.

    An operator should read it in a refusal.  It also has to be a refusal
    rather than an exception because the caller above turns it into a fail-
    closed Gate decision, and an escaping exception would be one an outer
    handler might treat as retryable.
    """

    class _Unreachable:
        def open(self, request: object, timeout: float | None = None) -> None:  # noqa: ARG002
            raise urllib.error.URLError("no metadata server")

    _asking(monkeypatch, _Unreachable())

    refused = MetadataServerPrincipal().principal_id()

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE


def test_a_refusing_metadata_server_is_reported_by_its_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Refusing:
        def open(self, request: object, timeout: float | None = None) -> None:  # noqa: ARG002
            raise urllib.error.HTTPError(METADATA_EMAIL_URL, 403, "Forbidden", Message(), None)

    _asking(monkeypatch, _Refusing())

    refused = MetadataServerPrincipal().principal_id()

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE
    assert "403" in refused.error.detail


def test_an_empty_answer_is_malformed_rather_than_an_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _asking(monkeypatch, _Recording(body=b"   \n"))

    refused = MetadataServerPrincipal().principal_id()

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_MALFORMED


def test_a_non_ascii_answer_is_a_refusal_rather_than_a_decode_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _asking(monkeypatch, _Recording(body=b"\xff\xfe not ascii"))

    refused = MetadataServerPrincipal().principal_id()

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE


def test_the_answer_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not about this endpoint misbehaving.

    The process that holds the case record reads unbounded octets from nothing,
    including something on its own instance.
    """
    opener = _Recording(body=b"a" * (MAX_PRINCIPAL_OCTETS * 4))
    _asking(monkeypatch, opener)

    found = MetadataServerPrincipal().principal_id()

    assert isinstance(found, Ok)
    assert len(found.value) == MAX_PRINCIPAL_OCTETS
