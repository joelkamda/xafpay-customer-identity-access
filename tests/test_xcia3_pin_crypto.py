from __future__ import annotations

import pytest

from xcia.crypto import CredentialSecrets, create_verifier, normalize_phone, require_pin, verify_pin


@pytest.fixture
def credential_secrets() -> CredentialSecrets:
    return CredentialSecrets(b"xcia3 deterministic test credential root secret")


@pytest.mark.parametrize("pin", ["12345", "1234567", "12a456", " 12345"])
def test_pin_requires_exactly_six_digits(pin: str) -> None:
    with pytest.raises(ValueError, match="six digits"):
        require_pin(pin)


def test_scrypt_verifier_uses_random_salt_and_never_contains_pin(
    credential_secrets: CredentialSecrets,
) -> None:
    first = create_verifier("123456", credential_secrets)
    second = create_verifier("123456", credential_secrets)
    assert first != second
    assert "123456" not in first
    assert verify_pin("123456", first, credential_secrets)
    assert not verify_pin("654321", first, credential_secrets)


def test_phone_boundary_requires_normalized_e164() -> None:
    assert normalize_phone("+2348012345678") == "+2348012345678"
    with pytest.raises(ValueError, match="E.164"):
        normalize_phone("08012345678")


def test_credential_secret_fails_closed_when_too_short() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        CredentialSecrets(b"too-short")
