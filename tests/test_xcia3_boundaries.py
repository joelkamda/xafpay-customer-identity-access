from __future__ import annotations

from pathlib import Path

import pytest

from xcia.config import RuntimeEnvironment, Xcia3RuntimeSettings
from xcia.crypto import CredentialSecrets


def test_keyed_phone_values_are_stable_and_purpose_separated() -> None:
    first = CredentialSecrets(b"a" * 32)
    second = CredentialSecrets(b"b" * 32)
    phone = "+2348012345678"
    assert first.opaque_digest("xcia3/phone-lookup", phone) == first.opaque_digest(
        "xcia3/phone-lookup", phone
    )
    assert first.opaque_digest("xcia3/phone-lookup", phone) != second.opaque_digest(
        "xcia3/phone-lookup", phone
    )


def test_production_configuration_fails_closed() -> None:
    configuration = Xcia3RuntimeSettings(credential_secret_env="XCIA3_TEST_SECRET")
    with pytest.raises(ValueError):
        configuration.validate_for_environment(RuntimeEnvironment.PRODUCTION, b"a" * 32)
    with pytest.raises(ValueError):
        configuration.validate_for_environment(RuntimeEnvironment.TEST, None)


def test_no_real_provider_or_financial_pin_surface() -> None:
    source_root = Path(__file__).parents[1] / "src" / "xcia"
    content = "\n".join(path.read_text(encoding="utf-8") for path in source_root.rglob("*.py"))
    forbidden = ("twilio", "whatsapp", "mtn momo", "orange money", "bank pin")
    assert all(term not in content.lower() for term in forbidden)
