from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from xcia.domain import CustomerAuthAssertionClaims
from xcia.policies import BrowserSecurityPolicy, SubjectPolicy, SubjectRepresentation


def test_browser_policy_matches_frozen_baseline() -> None:
    policy = BrowserSecurityPolicy()
    assert policy.httponly is True
    assert policy.secure is True
    assert policy.domain is None
    assert policy.path == "/"
    assert policy.samesite == "lax"
    assert policy.cookie_name.startswith("__Host-")
    assert policy.csrf_required is True
    assert policy.exact_origin_validation is True
    assert policy.wildcard_credentialed_cors is False


@pytest.mark.parametrize(
    "representation",
    [
        SubjectRepresentation.EMAIL,
        SubjectRepresentation.PHONE,
        SubjectRepresentation.NAME,
        SubjectRepresentation.DISPLAY_NAME,
        SubjectRepresentation.XBOS_PARTY_ID,
        SubjectRepresentation.WALLET_ID,
        SubjectRepresentation.CUSTOMER_DATABASE_ID,
        SubjectRepresentation.MERCHANT_ID,
        SubjectRepresentation.PAYMENT_ACCOUNT,
        SubjectRepresentation.FINANCIAL_ACCOUNT,
        SubjectRepresentation.ECONOMIC_ACCOUNT,
        SubjectRepresentation.PROVIDER_CREDENTIAL,
    ],
)
def test_forbidden_subject_representation_is_rejected(
    representation: SubjectRepresentation,
) -> None:
    with pytest.raises(ValueError):
        SubjectPolicy.create_server_issued_subject(
            value="sub_01JTESTOPAQUE000000000001",
            relying_party="wallet",
            environment="test",
            representation=representation,
        )


@pytest.mark.parametrize(
    "value",
    [
        "customer@example.com",
        "+237600000000",
        "John Doe",
        "wallet:1234567890123456",
        "merchant:1234567890123456",
        "financial:1234567890123456",
    ],
)
def test_pii_or_resource_shaped_subject_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        SubjectPolicy.create_server_issued_subject(
            value=value,
            relying_party="wallet",
            environment="test",
        )


def test_opaque_pairwise_subject_is_accepted() -> None:
    subject = SubjectPolicy.create_server_issued_subject(
        value="sub_01JTESTOPAQUE000000000001",
        relying_party="wallet",
        environment="test",
    )
    assert subject.relying_party == "wallet"
    assert subject.environment == "test"


@pytest.mark.parametrize(
    "missing",
    ["iss", "sub", "aud", "iat", "nbf", "exp", "jti", "sid", "auth_time", "cnf"],
)
def test_assertion_required_claims_cannot_be_omitted(
    claim_factory: Callable[..., CustomerAuthAssertionClaims],
    missing: str,
) -> None:
    valid = claim_factory()
    payload = valid.model_dump()
    del payload[missing]
    with pytest.raises(ValidationError):
        CustomerAuthAssertionClaims.model_validate(payload)
