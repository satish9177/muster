"""The half of Q-12(a) that a *request* decides, resolved for one rebuild.

Check Q-12(a) has two halves (**section 12.4.3**).  The first is a property of
the pinned bundle: the predicate schema names which source classes may attest a
predicate at all.  The second is a property of the *solicitation*::

    and where the payload cites a ``request_id``, also
    ``in target.permitted_source_classes`` for that ``EvidenceTarget``

An evidence request narrows, per proposition, which classes may answer it.  A
case that asked the site access-control system for ``present_on_site`` has not
asked the payroll system, and a permitted-class list nothing compares against
is not a control -- which is the defect the whole milestone exists to close.

**Why this needs a type rather than a store lookup.**  ``rebuild`` reads no
store, no clock and no registry handle, so the requests a rebuild judges
citations against arrive as an argument, exactly as the bundle and the two
authority snapshots do.  And like them they are not *free* arguments: every one
is checked here against the digest under which it was cited before a single
clause reads it.

**Why resolving a caller-supplied request is not "consulting mutable current
state".**  The digest being resolved is inside the signed acquisition payload,
which is inside a transcript entry, which is inside the transcript prefix the
revision pins.  SHA-256 binds the digest to exactly one request, so a caller
handing in a *different* request under that digest is refused by
:meth:`SolicitationView.of` rather than believed.  What a caller can do is fail
to supply one, and that is the reason absence means "not solicited" instead of
"refused": see :meth:`SolicitationView.permitted_source_classes`.

**Where the unevadable half lives.**  Nothing here can be driven by what the
case *issued*, because a rebuild has no view of outstanding requests and must
not acquire one -- outstanding-ness is present-tense state, and a historical
replay that consulted it would decide a settled case by what is outstanding
today.  So a source that cites a digest naming nothing escapes the narrowing
*here*, and is refused at admission instead, where the check is driven by the
case's outstanding set and reads no field the signer controls.  The two halves
are deliberate: admission refuses what a signer can choose, and rebuild
re-establishes, from pinned artifacts alone, what admission concluded -- because
the control plane's verdict is never inherited, only reproduced.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from muster.core.evidence.requests import EvidenceRequest
from muster.core.values.symbols import SymbolRef
from muster.core.wire.digests import Digest


@dataclass(frozen=True, slots=True)
class SolicitationView:
    """The evidence requests one rebuild resolves citations against.

    Built once per rebuild and keyed by the digest each request is cited under,
    so a lookup is exact and there is no scan whose order could decide anything.
    """

    tenant_id: str
    case_id: str
    requests: Mapping[Digest, EvidenceRequest]

    @staticmethod
    def of(tenant_id: str, case_id: str, requests: Iterable[EvidenceRequest]) -> SolicitationView:
        """Index requests by their own digest. Nothing is filtered away here.

        A request is keyed by ``request.digest()`` and by nothing a caller
        passed alongside it, so a caller cannot file one request under
        another's identifier -- the identity is recomputed from the content
        rather than accepted.  Under SHA-256 that is the whole of substitution
        resistance: a tampered request lands under a different key, and the
        citation that named the original resolves to nothing there.

        **A request belonging to another case is kept, not dropped**, and the
        difference decides an attack.  Dropping it would make a borrowed
        citation indistinguishable from an unresolvable one -- and an
        unresolvable citation means *volunteered*, which is an acceptance.  So
        dropping would convert "this receipt answers a request issued by another
        case" into "this receipt answers nothing", which is exactly the
        laundering :meth:`permitted_source_classes` refuses.  The binding is
        therefore checked at lookup, where it can produce a refusal instead of
        an absence.
        """
        return SolicitationView(
            tenant_id, case_id, {request.digest(): request for request in requests}
        )

    def permitted_source_classes(
        self, cited: Digest, proposition: SymbolRef, declared: frozenset[str]
    ) -> frozenset[str] | None:
        """``declared`` narrowed by the cited request, or ``None`` to refuse.

        The returned set satisfies **both** halves of Q-12(a), so the caller
        compares against one set and cannot apply one half and forget the other.

        Four outcomes.

        *The citation resolves to one of this case's requests, and it names this
        proposition.*  The answer is the intersection.  A request that narrowed
        answerers to one class cannot be answered by another, whatever the
        bundle would have allowed on its own -- and an intersection is what makes
        that true regardless of which set is smaller.

        *It resolves to one of this case's requests, and that request is silent
        about this proposition.*  The request has no opinion, so nothing is
        narrowed.  A request that asked about one proposition has not thereby
        forbidden every other.

        *It resolves to nothing.*  Unsolicited -- **volunteered** -- evidence,
        which is legitimate: a source offering an observation it holds a grant
        for is exactly what the registry exists to authorize.  Nothing is
        narrowed, and Q-12(b) through (f) still decide whether the key may say
        it.  Refusing here instead would be a blanket rule the ratified clause
        does not state -- it says "*where* the payload cites a request_id" -- and
        it would retroactively strip effect from volunteered evidence a case had
        already admitted.

        *It resolves to a request issued by another tenant or another case.*
        **Refused**, and this one is not a narrowing question at all.  One
        case's solicitation must not reach into another in either direction, and
        the admission path refuses a borrowed citation outright for that reason.
        A rebuild that treated it as volunteered would be laxer than the door the
        entry came through -- so an entry that reached the transcript some other
        way, an operator with SQL or an admission from an older build, would
        become consequential on a condition admission would have refused.
        ``None`` is that refusal, and the caller records it as a non-effect
        rather than raising: evidence that is not admissible must have no
        effect, and the record must still say that it arrived.
        """
        request = self.requests.get(cited)
        if request is None:
            return declared
        if request.tenant_id != self.tenant_id or request.case_id != self.case_id:
            return None
        for target in request.targets:
            if target.proposition == proposition:
                return declared & frozenset(target.permitted_source_classes)
        return declared
