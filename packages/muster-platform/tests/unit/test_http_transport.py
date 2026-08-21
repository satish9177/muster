"""The control plane's one outbound edge, driven without a socket.

Every test here is about a way the control plane's identity token or a case's
assignment could reach somewhere nobody chose. The opener is replaced with a
recording stand-in, so what is exercised is the module's own decisions --
which endpoint it will call, whether it mints a token first, what it does with
a redirect, and how much it will read back.

The one thing not exercised is the network itself, which is exactly the part
that has no decision in it.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from io import BytesIO
from typing import Any

import pytest

from muster.core.evidence.delivery import TransportError, TransportFailure
from muster.core.results import Err, InvariantViolation, Ok, Result
from muster.platform.adapters.http import (
    MAX_RESPONSE_OCTETS,
    METADATA_IDENTITY_FORMAT,
    HttpAcquisitionTransport,
    IdentityTokens,
    MetadataServerTokens,
    RefuseRedirects,
    TokenError,
    TokenFailure,
    direct_opener,
)


def _handlers(opener: urllib.request.OpenerDirector) -> list[Any]:
    """The handler list an opener assembled.

    Reached through ``getattr`` because ``OpenerDirector`` does not declare
    the attribute in its stubs. It is a documented part of the shape -- what
    is being asserted is which handlers ended up installed, which is
    precisely what the module's two substitutions decide.
    """
    found = getattr(opener, "handlers", [])
    assert isinstance(found, list)
    return found


HOST = "agent-site-a-abc.a.run.app"
ENDPOINT = f"https://{HOST}"
HOSTS = frozenset({HOST})


@dataclass(frozen=True, slots=True)
class _Token(IdentityTokens):
    """A token source that records the audiences it was asked for."""

    minted: list[str] = field(default_factory=list)
    value: str = "an-identity-token"

    def token(self, audience: str) -> Result[str, TokenError]:
        self.minted.append(audience)
        return Ok(self.value)


@dataclass(frozen=True, slots=True)
class _Refusing(IdentityTokens):
    def token(self, audience: str) -> Result[str, TokenError]:  # noqa: ARG002
        return Err(TokenError(TokenFailure.UNAVAILABLE, "not on Google Cloud"))


class _Answer(BytesIO):
    """A response body, in the shape a URL opener hands back."""

    def __enter__(self) -> _Answer:
        return self

    def __exit__(self, *_excinfo: object) -> None:
        self.close()


@dataclass
class _Recording:
    """A stand-in opener that records requests and replays a fixed answer."""

    body: bytes = b"answered"
    requests: list[urllib.request.Request] = field(default_factory=list)

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> _Answer:  # noqa: ARG002
        self.requests.append(request)
        return _Answer(self.body)


def _transport(tokens: IdentityTokens, **changes: Any) -> HttpAcquisitionTransport:
    return HttpAcquisitionTransport(tokens=tokens, hosts=HOSTS, **changes)


def _deliver(
    monkeypatch: pytest.MonkeyPatch,
    opener: _Recording,
    *,
    endpoint: str = ENDPOINT,
    tokens: IdentityTokens | None = None,
) -> Result[bytes, TransportError]:
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: opener)
    return _transport(tokens if tokens is not None else _Token()).deliver(
        endpoint_ref=endpoint, assignment=b"an-assignment"
    )


#  ---- which endpoints it will call ----------------------------------------


def test_a_cataloged_host_is_called_with_the_assignment_and_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = _Recording()
    tokens = _Token()
    answered = _deliver(monkeypatch, opener, tokens=tokens)
    assert isinstance(answered, Ok), answered
    assert answered.value == b"answered"

    (request,) = opener.requests
    assert request.full_url == f"{ENDPOINT}/acquire"
    assert request.data == b"an-assignment"
    assert request.get_header("Authorization") == "Bearer an-identity-token"
    #  Per audience, and the audience is the service, not the route.
    assert tokens.minted == [ENDPOINT]


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://agent-site-a-abc.a.run.app",
        "gs://agent-site-a-abc.a.run.app",
        "file:///etc/passwd",
        "agent-site-a-abc.a.run.app",
    ],
)
def test_only_https_is_called(monkeypatch: pytest.MonkeyPatch, endpoint: str) -> None:
    opener = _Recording()
    tokens = _Token()
    refused = _deliver(monkeypatch, opener, endpoint=endpoint, tokens=tokens)
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.ENDPOINT_UNKNOWN
    assert not opener.requests
    assert not tokens.minted, "a token was minted for an endpoint we will not call"


def test_a_host_outside_the_deployment_is_refused_before_a_token_is_minted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The catalog is signed and can still be wrong.

    A profile naming somebody else's host would otherwise get a Google-signed
    token for that host and the whole assignment body -- tenant, case, request,
    subject, propositions -- posted to it.
    """
    opener = _Recording()
    tokens = _Token()
    refused = _deliver(monkeypatch, opener, endpoint="https://attacker.example", tokens=tokens)
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.ENDPOINT_UNKNOWN
    assert not tokens.minted
    assert not opener.requests


def test_userinfo_cannot_disguise_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """``https://agent-site-a…@attacker.example/`` resolves to the attacker."""
    opener = _Recording()
    tokens = _Token()
    refused = _deliver(
        monkeypatch, opener, endpoint=f"https://{HOST}@attacker.example", tokens=tokens
    )
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.ENDPOINT_UNKNOWN
    assert not tokens.minted


def test_a_transport_that_names_no_host_cannot_be_built() -> None:
    """An empty allowlist would read as "anybody", which is how one stops being one."""
    with pytest.raises(InvariantViolation):
        HttpAcquisitionTransport(tokens=_Token(), hosts=frozenset())


#  ---- what it does with what comes back -----------------------------------


def test_a_redirect_never_carries_the_token_onwards() -> None:
    """The default opener follows redirects and keeps the Authorization header.

    The responder is the untrusted party in this exchange, so a 3xx from it is
    an endpoint refusing rather than an instruction to re-send a credential.
    """
    handler = RefuseRedirects()
    request = urllib.request.Request(  # noqa: S310 - never opened, only inspected
        f"{ENDPOINT}/acquire", headers={"Authorization": "Bearer secret"}
    )
    assert (
        handler.redirect_request(request, None, 302, "Found", None, "http://attacker.example/")
        is None
    )


def test_the_opener_registers_no_proxy_handler_at_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inherited ``http_proxy`` would otherwise see the identity request.

    Passing an empty ``ProxyHandler`` does two things, and the second is the
    one that matters: it displaces the default handler that reads the
    environment, and it registers no protocol methods of its own -- so the
    opener ends up with *no* proxy handler, and there is nothing left to
    consult a variable with.

    Asserted against an environment that actually sets one, because an
    assertion about proxy behaviour taken with no proxy configured is an
    assertion about nothing.
    """
    monkeypatch.setenv("http_proxy", "http://a-proxy.example:3128")
    monkeypatch.setenv("https_proxy", "http://a-proxy.example:3128")

    handlers = _handlers(direct_opener())
    assert not [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert not [h for h in handlers if type(h).__name__ == "ProxyHandler"]

    #  And the default opener, for contrast: this is what the module would have
    #  used, and it does consult the environment.
    assert [
        h
        for h in _handlers(urllib.request.build_opener())
        if isinstance(h, urllib.request.ProxyHandler)
    ]


def test_the_opener_uses_the_refusing_redirect_handler() -> None:
    """The default would follow a redirect and re-send the Authorization header."""
    redirects = [
        handler
        for handler in _handlers(direct_opener())
        if isinstance(handler, urllib.request.HTTPRedirectHandler)
    ]
    assert redirects
    assert all(isinstance(handler, RefuseRedirects) for handler in redirects)


def test_an_oversized_response_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The agent caps what it reads from the control plane; this is the other way."""
    opener = _Recording(body=b"x" * (MAX_RESPONSE_OCTETS + 1))
    refused = _deliver(monkeypatch, opener)
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.ENDPOINT_REFUSED


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (401, TransportFailure.IDENTITY_REFUSED),
        (403, TransportFailure.IDENTITY_REFUSED),
        (400, TransportFailure.ENDPOINT_REFUSED),
        (500, TransportFailure.ENDPOINT_REFUSED),
    ],
)
def test_an_http_failure_is_typed_by_what_it_means(
    monkeypatch: pytest.MonkeyPatch, code: int, expected: TransportFailure
) -> None:
    """An identity refusal and an endpoint refusal need different operators."""

    class _Failing:
        def open(self, request: object, timeout: float | None = None) -> None:  # noqa: ARG002
            raise urllib.error.HTTPError(ENDPOINT, code, "refused", Message(), None)

    failing = _Failing()
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: failing)
    refused = _transport(_Token()).deliver(endpoint_ref=ENDPOINT, assignment=b"a")
    assert isinstance(refused, Err), refused
    assert refused.error.failure is expected


def test_an_unreachable_endpoint_is_a_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Unreachable:
        def open(self, request: object, timeout: float | None = None) -> None:  # noqa: ARG002
            raise urllib.error.URLError("no route to host")

    unreachable = _Unreachable()
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: unreachable)
    refused = _transport(_Token()).deliver(endpoint_ref=ENDPOINT, assignment=b"a")
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.UNREACHABLE


def test_a_process_with_no_cloud_identity_reports_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """And nothing is sent: an unauthenticated assignment is not sent at all."""
    opener = _Recording()
    refused = _deliver(monkeypatch, opener, tokens=_Refusing())
    assert isinstance(refused, Err), refused
    assert refused.error.failure is TransportFailure.IDENTITY_REFUSED
    assert not opener.requests


def test_the_metadata_request_names_the_audience_and_the_flavour_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The header is what makes the endpoint unreachable by luring a fetcher."""
    opener = _Recording(body=b"a-token\n")
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: opener)
    minted = MetadataServerTokens().token(ENDPOINT)
    assert isinstance(minted, Ok), minted
    assert minted.value == "a-token"

    (request,) = opener.requests
    assert request.get_header("Metadata-flavor") == "Google"
    assert "audience=https%3A%2F%2F" in request.full_url


def test_the_minted_token_is_asked_to_carry_the_caller_s_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``format=full``, and the agent on the other end is why.

    An agent decides whether it will do work for a caller by comparing the
    token's ``email`` claim against the service accounts its deployment names.
    The metadata server's default format does not include ``email``; only
    ``full`` does. A token minted without it carries the opaque numeric ``sub``
    instead, which matches nothing in that list -- so every assignment the
    control plane sends is refused, in production only, while the operator's
    smoke test mints its own token through ``gcloud --include-email`` and
    passes.
    """
    opener = _Recording(body=b"a-token\n")
    monkeypatch.setattr("muster.platform.adapters.http.direct_opener", lambda: opener)
    assert isinstance(MetadataServerTokens().token(ENDPOINT), Ok)

    (request,) = opener.requests
    assert f"format={METADATA_IDENTITY_FORMAT}" in request.full_url


#  ---- how long it will wait -----------------------------------------------


def _default_wait() -> float:
    """The default the module ships, read from an instance.

    ``slots=True`` means the class attribute is a descriptor rather than the
    value, so the default is read the way a caller gets it: by building one.
    """
    return HttpAcquisitionTransport(tokens=_Token(), hosts=HOSTS).timeout_seconds


def test_the_wait_covers_a_cold_start_and_a_model_turn() -> None:
    """The default is arithmetic, and the arithmetic is checked against infra.

    A deployed source that has scaled to zero pays for its image pull, its
    interpreter import and its model client's start-up *inside* the request,
    and only then spends its own interpretation budget.  A client wait shorter
    than the service's own request bound would report ``TIMED_OUT`` for a
    source that was about to answer -- and the operator would go and debug the
    source.

    Read out of ``env.sh`` rather than restated here, because the number that
    matters is the deployed one and a copy of it in this file would be a copy
    that agrees until somebody changes one of them.
    """
    import re
    from pathlib import Path as _Path

    environment = (_Path(__file__).resolve().parents[4] / "infra" / "scripts" / "env.sh").read_text(
        encoding="utf-8"
    )
    declared = re.search(r"RUN_TIMEOUT:=(\d+)", environment)
    assert declared is not None, "env.sh declares no Cloud Run request timeout"
    service_bound = int(declared.group(1))

    assert _default_wait() > service_bound, (
        f"the control plane waits {_default_wait()}s and the service is allowed "
        f"{service_bound}s; the client would give up first"
    )


def test_the_wait_exceeds_the_interpreter_budget_a_deployed_agent_runs_under() -> None:
    """The other half of the same arithmetic, read from the agent's own default.

    Reached by file rather than by import, deliberately: this suite belongs to
    the control plane, and a test that imported the agent distribution to check
    a number would be the one import contract in this repository that nothing
    else needs.
    """
    import re
    from pathlib import Path as _Path

    configuration = (
        _Path(__file__).resolve().parents[4]
        / "packages"
        / "muster-agents"
        / "src"
        / "muster"
        / "agents"
        / "config.py"
    ).read_text(encoding="utf-8")
    declared = re.search(r"DEFAULT_TIMEOUT_SECONDS = ([\d.]+)", configuration)
    assert declared is not None, "the agent declares no interpreter timeout"
    assert _default_wait() > float(declared.group(1))


def test_a_deployment_may_shorten_the_wait_without_editing_the_module() -> None:
    """Configuration, not a constant: the value is a field with a default."""
    transport = HttpAcquisitionTransport(tokens=_Token(), hosts=HOSTS, timeout_seconds=5.0)
    assert transport.timeout_seconds == 5.0
