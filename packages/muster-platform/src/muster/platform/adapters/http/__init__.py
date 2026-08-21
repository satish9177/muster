"""Carrying an assignment to a deployed agent, under the control plane's identity.

The one outbound network edge the control plane has, and the only module in
this distribution that opens a socket.  It carries canonical octets to a URL
the catalog named, with a Google-signed identity token proving which service is
calling, and brings octets back.

**No client library, and the absence is the design.**  A cloud SDK in this
distribution would put a model client one transitive dependency away from the
process that holds the case salt and the whole record, and "the control plane
has no model dependency" would stop being checkable with ``pip show``.  What is
actually needed here is a POST and an identity token, and both have documented,
stable, dependency-free forms: the standard library's opener, and the metadata
server's identity endpoint, which is what a cloud SDK would call anyway.

**An identity token is not authority.**  It answers "which service is calling",
which is a question about the network.  Whether the receipt that comes back may
establish anything is check Q-12, decided later, in the admission path, against
a signed authority snapshot this module has never seen and could not reach.
Neither answer implies the other, and this module deliberately produces nothing
that an admission decision reads.

**Four rules keep the credential where it belongs**, and each one closes a way
the token or the assignment could reach somewhere nobody chose.

*The scheme is HTTPS and the host is on a list.*  An ``endpoint_ref`` travels in
a signed catalog snapshot, and the one thing a compromised or mistaken catalog
must not be able to do is make the control plane send an authenticated request
somewhere arbitrary.  A scheme check alone does not stop that -- an attacker's
host speaks HTTPS too -- so the deployment names the hosts it will call, and a
reference outside them is refused before a token is minted.

*Redirects are refused.*  The standard opener follows them and carries the
``Authorization`` header along, including to another host and to plain HTTP.
The responder is the party this whole milestone treats as untrusted, so a 3xx
from a source is an endpoint refusing rather than an instruction to re-send a
bearer credential somewhere else.

*Proxies are bypassed.*  The default opener honours ``http_proxy`` from the
environment, and the identity endpoint is plain HTTP by definition -- so an
inherited proxy setting is enough to route a request for this workload's own
credential through something that can read it, and answer it.

*The response is capped.*  The agent's own service caps what it will read from
the control plane; the asymmetry the other way would mean the control plane
defends the source and not itself.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from muster.core.evidence.delivery import TransportError, TransportFailure
from muster.core.results import Err, InvariantViolation, Ok, Result

#: Where a workload on Google Cloud asks for an identity token naming itself.
#: A documented, stable, credential-free endpoint reachable only from inside
#: the instance -- which is why the header below is required: it is what makes
#: the request impossible to trigger by luring the process into fetching a URL.
METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
METADATA_HEADER = ("Metadata-Flavor", "Google")

#: **Required, and the reason is the claim it adds.**  The metadata server's
#: default format omits ``email``; ``full`` includes it.  An agent decides
#: whether it will do work for a caller by comparing the token's ``email``
#: against the service-account addresses its deployment names, so a token
#: minted without this carries only the opaque numeric ``sub`` -- which matches
#: nothing in that list, and every assignment is refused with 403.
#:
#: It fails closed, which is why it would have survived a review and not a
#: deployment: the operator's smoke test mints its token through ``gcloud
#: --include-email`` and passes, and only the control plane's own calls fail.
METADATA_IDENTITY_FORMAT = "full"

HTTPS = "https://"
OCTETS = "application/octet-stream"

#: What a source may send back.  A response carries a handful of receipts, each
#: a few hundred octets; the cap is the same order as the agent's own inbound
#: cap and exists for the same reason -- an endpoint should not be able to make
#: the process that holds the case record allocate without bound.
MAX_RESPONSE_OCTETS = 1024 * 1024


class TokenFailure(Enum):
    UNAVAILABLE = "UNAVAILABLE"
    REFUSED = "REFUSED"


@dataclass(frozen=True, slots=True)
class TokenError:
    failure: TokenFailure
    detail: str


class IdentityTokens(Protocol):
    """Mint a Google-signed token naming this workload, for one audience.

    Per audience, never once: a token minted for one service is a credential
    that service can replay, so a single token reused across agents would let
    any one of them impersonate the control plane to the others.
    """

    def token(self, audience: str) -> Result[str, TokenError]: ...


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A 3xx is an endpoint refusing, never an instruction to re-send a token.

    The default handler re-issues the request at the new location and copies
    every header it did not strip; it strips ``Content-Length`` and
    ``Content-Type`` and it does not strip ``Authorization``.  So following a
    redirect from a source hands that source's chosen destination -- possibly
    another host, possibly plain HTTP -- a bearer credential naming the control
    plane.  Returning ``None`` makes the opener raise the original error, which
    this module reports as a refused endpoint.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,  # noqa: ARG002 - the library's signature
        fp: Any,  # noqa: ARG002
        code: int,  # noqa: ARG002
        msg: str,  # noqa: ARG002
        headers: Any,  # noqa: ARG002
        newurl: str,  # noqa: ARG002
    ) -> urllib.request.Request | None:
        return None


def direct_opener() -> urllib.request.OpenerDirector:
    """An opener that talks to the host it was given, and to nothing else.

    Two handlers replaced, both because the defaults are wrong here rather than
    merely unhelpful: an empty proxy handler overrides ``http_proxy`` and
    ``https_proxy`` from the environment, and a redirect handler that refuses
    turns a 3xx into a transport failure.
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirects())


@dataclass(frozen=True, slots=True)
class MetadataServerTokens(IdentityTokens):
    """The workload's own identity, from the instance metadata server.

    Holds no credential and cannot: the metadata server answers on the basis of
    *where the request came from*, so there is nothing here to rotate, nothing
    to store and nothing that survives the process.
    """

    timeout_seconds: float = 5.0

    def token(self, audience: str) -> Result[str, TokenError]:
        query = urllib.parse.urlencode({"audience": audience, "format": METADATA_IDENTITY_FORMAT})
        request = urllib.request.Request(  # noqa: S310 - a fixed, non-routable host
            f"{METADATA_IDENTITY_URL}?{query}",
            headers=dict((METADATA_HEADER,)),
            method="GET",
        )
        try:
            with direct_opener().open(request, timeout=self.timeout_seconds) as answer:
                return Ok(answer.read(MAX_RESPONSE_OCTETS).decode("ascii").strip())
        except urllib.error.HTTPError as refused:
            return Err(TokenError(TokenFailure.REFUSED, f"{refused.code} {refused.reason}"))
        except (urllib.error.URLError, TimeoutError, OSError) as unreachable:
            #  Not on Google Cloud, or the metadata server is unreachable.  A
            #  value rather than a raise, because "this process has no cloud
            #  identity" is a configuration fact an operator should read in a
            #  refusal rather than in a traceback.
            return Err(TokenError(TokenFailure.UNAVAILABLE, str(unreachable)))


@dataclass(frozen=True, slots=True)
class HttpAcquisitionTransport:
    """Deliver assignment octets to a deployed agent over authenticated HTTPS.

    ``hosts`` is the deployment's own list of agent hosts.  It is required and
    has no default, because a default would be either empty -- refusing
    everything -- or permissive, and a permissive default is the one an
    operator never notices they accepted.

    ``path`` is appended to the cataloged endpoint, so a catalog entry names a
    *service* rather than a route -- which keeps the route an implementation
    detail of this distribution and the catalog a directory of principals.

    ``timeout_seconds`` is how long the control plane waits, and the number is
    an arithmetic rather than a preference.  A source that has scaled to zero
    pays for its image pull, its interpreter import and its model client's
    start-up *inside* the request, and only then spends its own interpretation
    budget -- so the wait has to cover a cold start plus a model turn.  It is
    also deliberately **longer than the agent service's own request bound**: a
    client that gave up first would report ``TIMED_OUT`` for a source that was
    about to answer, and the operator would be debugging the wrong process.
    The default is the deployment's bound (180s) plus room for the answer to
    come back; a deployment that shortens one shortens both.

    Nothing here retries, so the wait is the whole budget for one round.
    """

    tokens: IdentityTokens
    hosts: frozenset[str]
    path: str = "/acquire"
    timeout_seconds: float = 210.0

    def __post_init__(self) -> None:
        if not self.hosts:
            raise InvariantViolation("a transport names the hosts it will call")

    def deliver(self, *, endpoint_ref: str, assignment: bytes) -> Result[bytes, TransportError]:
        addressed = self._audience(endpoint_ref)
        if isinstance(addressed, Err):
            return addressed
        audience = addressed.value

        minted = self.tokens.token(audience)
        if isinstance(minted, Err):
            return Err(
                TransportError(
                    TransportFailure.IDENTITY_REFUSED,
                    f"{minted.error.failure.value}: {minted.error.detail}",
                )
            )
        request = urllib.request.Request(  # noqa: S310 - scheme and host checked above
            f"{audience}{self.path}",
            data=assignment,
            headers={
                "Authorization": f"Bearer {minted.value}",
                "Content-Type": OCTETS,
                "Accept": OCTETS,
            },
            method="POST",
        )
        try:
            with direct_opener().open(request, timeout=self.timeout_seconds) as answer:
                body: bytes = answer.read(MAX_RESPONSE_OCTETS + 1)
        except urllib.error.HTTPError as refused:
            failure = (
                TransportFailure.IDENTITY_REFUSED
                if refused.code in (401, 403)
                else TransportFailure.ENDPOINT_REFUSED
            )
            return Err(TransportError(failure, f"{refused.code} {refused.reason}"))
        except TimeoutError:
            return Err(
                TransportError(TransportFailure.TIMED_OUT, f"{self.timeout_seconds:g}s elapsed")
            )
        except (urllib.error.URLError, OSError) as unreachable:
            return Err(TransportError(TransportFailure.UNREACHABLE, str(unreachable)))

        if len(body) > MAX_RESPONSE_OCTETS:
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_REFUSED,
                    f"the response exceeds {MAX_RESPONSE_OCTETS} octets",
                )
            )
        return Ok(body)

    def _audience(self, endpoint_ref: str) -> Result[str, TransportError]:
        """The endpoint this reference names, if this deployment will call it.

        Scheme, then userinfo, then host.  Userinfo matters more than it looks:
        ``https://agent.example@attacker.example/`` has a hostname of
        ``attacker.example`` and reads, to somebody skimming a catalog, like
        the first name in it.
        """
        if not endpoint_ref.startswith(HTTPS):
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_UNKNOWN,
                    f"{endpoint_ref!r} is not an https endpoint this transport will call",
                )
            )
        split = urllib.parse.urlsplit(endpoint_ref)
        if split.username or split.password:
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_UNKNOWN, f"{endpoint_ref!r} carries userinfo"
                )
            )
        if split.hostname is None or split.hostname not in self.hosts:
            return Err(
                TransportError(
                    TransportFailure.ENDPOINT_UNKNOWN,
                    f"{split.hostname!r} is not a host this deployment calls",
                )
            )
        return Ok(endpoint_ref.rstrip("/"))
