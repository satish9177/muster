"""Who called, as a question separate from what they may attest.

Two questions, two layers, and the whole trust model depends on nobody
collapsing them:

    network identity   "which service made this call?"
                       answered by a Google-signed identity token, here

    source authority   "may this key attest this predicate, for this resource,
                        in this tenant, now?"
                       answered by check Q-12, in the control plane, against a
                       signed authority snapshot this module has never seen

**Neither implies the other, in either direction.**  An identity permitted to
invoke a site agent has no authority to attest anything -- it is a caller, not
a source.  And a key holding a grant over ``present_on_site`` at ``SITE-A``
cannot thereby invoke a Cloud Run service; invocation is an IAM binding and has
no relationship to a signed grant.  A deployment that used one to decide the
other would have one control where it thought it had two.

So what this module produces is deliberately small: a caller's identity, or a
refusal.  It never returns anything an admission decision reads, and there is
no field on the way out through which it could.

**A token names its audience and the audience is checked.**  A token minted for
another service is a valid Google-signed token and is not a token for this one;
accepting it would let any service anyone can invoke replay its own credential
here.  The audience is configuration, and a service that does not know its own
URL refuses everything rather than accepting anything.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from muster.core.results import Err, InvariantViolation, Ok, Result


class IdentityFailure(Enum):
    """Why a caller was refused before its request was read at all."""

    #: No bearer token was presented.
    ABSENT = "ABSENT"
    #: The token did not verify: wrong signature, expired, malformed, or minted
    #: for a different audience.
    INVALID = "INVALID"
    #: The token verified and names a caller this service does not serve.
    NOT_PERMITTED = "NOT_PERMITTED"


@dataclass(frozen=True, slots=True)
class IdentityError:
    failure: IdentityFailure
    detail: str


class CallerIdentity(Protocol):
    """Resolve the caller of one request, or refuse it."""

    def verify(self, bearer: str | None) -> Result[str, IdentityError]: ...


@dataclass(frozen=True, slots=True)
class GoogleIdentityToken(CallerIdentity):
    """A Google-signed identity token, checked for audience and for caller.

    ``permitted_callers`` is the set of service-account addresses allowed to
    send this agent assignments -- ordinarily one, the control plane's.  It is
    a second control beside the IAM invoker binding rather than a replacement
    for it: the binding decides who can reach the service at all, and this
    decides who the service will do work for, and having both means a
    mis-scoped binding is not immediately an open door.
    """

    audience: str
    permitted_callers: frozenset[str]

    def __post_init__(self) -> None:
        if not self.audience:
            raise InvariantViolation("a service that checks tokens names its own audience")
        if not self.permitted_callers:
            #  An empty set would read as "anybody", which is how an allowlist
            #  becomes a formality.  A service nobody may call is refused at
            #  construction rather than deployed and quietly open.
            raise InvariantViolation("a service names the callers it serves")

    def verify(self, bearer: str | None) -> Result[str, IdentityError]:
        if not bearer:
            return Err(IdentityError(IdentityFailure.ABSENT, "no bearer token"))
        #  Imported inside the call rather than at module scope: verification
        #  reaches Google's certificate endpoint, and a module that dragged an
        #  HTTP transport in at import time would make every test of this
        #  distribution pay for a dependency only a deployed service uses.
        from google.auth.transport import requests as google_requests  # noqa: PLC0415
        from google.oauth2 import id_token  # noqa: PLC0415

        #  Bound to a typed name before it is called.  The library ships type
        #  information for almost everything and not for this one function, and
        #  a blanket exemption for the package would take the check off every
        #  other call in it -- so the gap is narrowed to the one symbol that has
        #  it, in the one place that uses it.
        verify: Callable[..., Mapping[str, object]] = id_token.verify_oauth2_token
        try:
            claims = verify(bearer, google_requests.Request(), audience=self.audience)
        except Exception as failure:
            #  Broad, and total by contract.  An expired token, a wrong
            #  audience, a malformed segment, a certificate fetch failure and a
            #  library type this package has never heard of all mean one thing
            #  to a caller: you are not authenticated here.
            return Err(
                IdentityError(IdentityFailure.INVALID, f"{type(failure).__name__}: {failure}"[:200])
            )
        caller = str(claims.get("email") or claims.get("sub") or "")
        if caller not in self.permitted_callers:
            return Err(
                IdentityError(
                    IdentityFailure.NOT_PERMITTED, f"{caller or 'an unnamed caller'} is not served"
                )
            )
        return Ok(caller)


@dataclass(frozen=True, slots=True)
class UncheckedCaller(CallerIdentity):
    """Accepts anybody, under a name that makes a deployment review notice.

    For a laptop, where there is no identity infrastructure to check against
    and the only caller is the developer running the demo.  Named for what it
    does rather than for what it is for, so that finding it in a deployed
    service's composition is finding a defect rather than reading a setting.
    """

    name: str = "unchecked-local-caller"

    def verify(
        self,
        bearer: str | None,  # noqa: ARG002 - the port's argument, deliberately unread
    ) -> Result[str, IdentityError]:
        return Ok(self.name)
