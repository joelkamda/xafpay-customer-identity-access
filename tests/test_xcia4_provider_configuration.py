from __future__ import annotations

import pytest

from xcia.adapters import InfobipHttpResponse, compose_phone_verification_provider
from xcia.config import RuntimeEnvironment, Xcia3RuntimeSettings


class NoNetworkTransport:
    def post(self, **_: object) -> InfobipHttpResponse:
        raise AssertionError("network transport must not run in configuration tests")


def infobip_settings(**overrides: object) -> Xcia3RuntimeSettings:
    values: dict[str, object] = {
        "credential_secret_env": "XCIA3_TEST_SECRET",
        "phone_provider": "infobip_2fa",
        "infobip_base_url": "https://api.infobip.test",
        "infobip_2fa_application_id": "application-test",
        "infobip_2fa_message_id": "message-test",
        "infobip_sender_id": "XafPay",
    }
    values.update(overrides)
    return Xcia3RuntimeSettings.model_validate(values)


def test_provider_selection_is_configuration_driven(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XAFPAY_XCIA_INFOBIP_API_KEY", "test-not-a-real-infobip-key")
    provider = compose_phone_verification_provider(
        settings=infobip_settings(),
        environment=RuntimeEnvironment.TEST,
        fake_secret=b"x" * 32,
        transport=NoNetworkTransport(),
    )
    assert type(provider).__name__ == "InfobipPhoneVerificationAdapter"


@pytest.mark.parametrize(
    "field",
    [
        "infobip_base_url",
        "infobip_2fa_application_id",
        "infobip_2fa_message_id",
        "infobip_sender_id",
    ],
)
def test_incomplete_infobip_configuration_fails_closed(field: str) -> None:
    with pytest.raises(ValueError, match="Infobip"):
        infobip_settings(**{field: None}).require_infobip_configuration()


def test_production_requires_https_and_secret_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = infobip_settings(infobip_base_url="http://api.infobip.test")
    with pytest.raises(ValueError, match="HTTPS"):
        settings.validate_for_environment(RuntimeEnvironment.PRODUCTION, b"x" * 32)
    settings = infobip_settings()
    monkeypatch.delenv("XAFPAY_XCIA_INFOBIP_API_KEY", raising=False)
    with pytest.raises(ValueError, match="API key"):
        settings.validate_for_environment(RuntimeEnvironment.PRODUCTION, b"x" * 32)


def test_fake_is_test_only_and_invalid_selector_fails_closed() -> None:
    fake = Xcia3RuntimeSettings(credential_secret_env="XCIA3_TEST_SECRET")
    assert fake.phone_provider == "deterministic_fake"
    with pytest.raises(ValueError, match="forbidden"):
        fake.validate_for_environment(RuntimeEnvironment.PRODUCTION, b"x" * 32)
    with pytest.raises(ValueError, match="supported"):
        Xcia3RuntimeSettings(
            credential_secret_env="XCIA3_TEST_SECRET",
            phone_provider="unknown",
        )
