"""Who a deployed Gate accepts, and every way it refuses.

The deployed Gate's caller is the identity the *runtime* reports, and every
test here is about that sentence being true rather than aspirational: nothing
in :mod:`muster.platform.gate.cloud` reads an argument, a header, a request
field or a model's output, so the only way to change who the Gate thinks is
asking is to change what the runtime answers.

``resolve_cloud_gate_authority`` is a pure function over a port, which is why
it can be exercised exhaustively here.  The one implementation of that port --
``MetadataServerPrincipal`` -- is exercised separately, because it opens a
socket and this file must not.
"""

from __future__ import annotations

from dataclasses import dataclass

from muster.core.results import Err, Ok, Result
from muster.platform.gate.authority import ExecutionGrant, GateCaller
from muster.platform.gate.cloud import (
    CloudExecutionAuthorityConfiguration,
    CloudPrincipalError,
    CloudPrincipalFailure,
    RuntimePrincipal,
    resolve_cloud_gate_authority,
)

PRINCIPAL = "muster-control-plane@muster-project.iam.gserviceaccount.com"
OTHER = "muster-migrator@muster-project.iam.gserviceaccount.com"


@dataclass(frozen=True, slots=True)
class _Runtime(RuntimePrincipal):
    """Whatever the runtime is pretending to answer this time."""

    answer: Result[str, CloudPrincipalError]

    def principal_id(self) -> Result[str, CloudPrincipalError]:
        return self.answer


def _configuration(**overrides: str) -> CloudExecutionAuthorityConfiguration:
    fields = {
        "expected_principal_id": PRINCIPAL,
        "tenant_id": "ALPHA",
        "action_kind": "PAY",
        "gate_id": "cloud-action-gate/v1",
        "executor_id": "sandbox-payment-cloud/v1",
    }
    fields.update(overrides)
    return CloudExecutionAuthorityConfiguration(**fields)


def test_the_observed_identity_becomes_the_caller_and_holds_exactly_one_grant() -> None:
    resolved = resolve_cloud_gate_authority(_Runtime(Ok(PRINCIPAL)), _configuration())

    assert isinstance(resolved, Ok), resolved
    assert resolved.value.caller == GateCaller(PRINCIPAL)
    assert resolved.value.authority.grants == (
        ExecutionGrant(
            principal_id=PRINCIPAL,
            tenant_id="ALPHA",
            action_kind="PAY",
            gate_id="cloud-action-gate/v1",
            executor_id="sandbox-payment-cloud/v1",
        ),
    )


def test_the_grant_is_exact_in_every_field() -> None:
    """Not a prefix, not a wildcard, not "any tenant".

    Stated by asking the authority the four questions it answers, each with one
    field changed.  A grant that matched any of them would be a grant a second
    deployment, a second tenant or a second executor could use.
    """
    resolved = resolve_cloud_gate_authority(_Runtime(Ok(PRINCIPAL)), _configuration())
    assert isinstance(resolved, Ok)
    authority = resolved.value.authority
    caller = resolved.value.caller

    assert authority.permits(
        caller,
        tenant_id="ALPHA",
        action_kind="PAY",
        gate_id="cloud-action-gate/v1",
        executor_id="sandbox-payment-cloud/v1",
    )
    for wrong in (
        {"tenant_id": "BETA"},
        {"action_kind": "REFUND"},
        {"gate_id": "local-action-gate/v1"},
        {"executor_id": "sandbox-payment/v1"},
    ):
        arguments = {
            "tenant_id": "ALPHA",
            "action_kind": "PAY",
            "gate_id": "cloud-action-gate/v1",
            "executor_id": "sandbox-payment-cloud/v1",
            **wrong,
        }
        assert not authority.permits(caller, **arguments), wrong
    assert not authority.permits(
        GateCaller(OTHER),
        tenant_id="ALPHA",
        action_kind="PAY",
        gate_id="cloud-action-gate/v1",
        executor_id="sandbox-payment-cloud/v1",
    )


def test_a_workload_running_as_another_identity_is_refused() -> None:
    """The commonest real failure: a job deployed under the wrong account."""
    refused = resolve_cloud_gate_authority(_Runtime(Ok(OTHER)), _configuration())

    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.PRINCIPAL_MISMATCH
    #  The identity that actually ran is named, because that is what an
    #  operator fixes.  The configured one is not restated: their own
    #  deployment already says it.
    assert OTHER in refused.error.detail
    assert PRINCIPAL not in refused.error.detail


def test_no_runtime_identity_is_a_refusal_and_not_a_default() -> None:
    """Not on Google Cloud, or the metadata server is unreachable.

    A Gate that fell back to its configured principal here would be a Gate
    whose authority list decided nothing: the deployment would be asserting
    both halves of the comparison.
    """
    unavailable = CloudPrincipalError(
        CloudPrincipalFailure.RUNTIME_IDENTITY_UNAVAILABLE, "no metadata server"
    )
    refused = resolve_cloud_gate_authority(_Runtime(Err(unavailable)), _configuration())

    assert isinstance(refused, Err)
    assert refused.error is unavailable


def test_an_answer_that_is_not_a_service_account_identity_is_refused() -> None:
    for answer in ("", "   ", "muster-control-plane", "123456789"):
        refused = resolve_cloud_gate_authority(_Runtime(Ok(answer)), _configuration())
        assert isinstance(refused, Err), answer
        assert refused.error.failure is CloudPrincipalFailure.RUNTIME_IDENTITY_MALFORMED


def test_an_incomplete_deployment_configuration_is_named_field_by_field() -> None:
    """A missing variable is a decision nobody made, not a value to default."""
    for field in (
        "expected_principal_id",
        "tenant_id",
        "action_kind",
        "gate_id",
        "executor_id",
    ):
        refused = resolve_cloud_gate_authority(
            _Runtime(Ok(PRINCIPAL)), _configuration(**{field: ""})
        )
        assert isinstance(refused, Err), field
        assert refused.error.failure is CloudPrincipalFailure.AUTHORITY_NOT_CONFIGURED
        assert field in refused.error.detail


def test_configuration_is_checked_before_the_runtime_is_asked() -> None:
    """An unconfigured Gate refuses without opening a socket.

    Ordering, stated as a behaviour: the runtime here would raise if it were
    consulted, and an incomplete configuration must refuse before that.
    """

    @dataclass(frozen=True, slots=True)
    class _Explodes(RuntimePrincipal):
        def principal_id(self) -> Result[str, CloudPrincipalError]:
            raise AssertionError("the runtime was asked before configuration was checked")

    refused = resolve_cloud_gate_authority(_Explodes(), _configuration(tenant_id=""))
    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.AUTHORITY_NOT_CONFIGURED


def test_surrounding_whitespace_never_makes_two_identities_one() -> None:
    """A padded configuration value matches; a padded *different* one does not."""
    padded = resolve_cloud_gate_authority(
        _Runtime(Ok(f"  {PRINCIPAL}  ")), _configuration(expected_principal_id=f" {PRINCIPAL} ")
    )
    assert isinstance(padded, Ok)
    assert padded.value.caller == GateCaller(PRINCIPAL)

    refused = resolve_cloud_gate_authority(
        _Runtime(Ok(f" {OTHER} ")), _configuration(expected_principal_id=f" {PRINCIPAL} ")
    )
    assert isinstance(refused, Err)
    assert refused.error.failure is CloudPrincipalFailure.PRINCIPAL_MISMATCH
