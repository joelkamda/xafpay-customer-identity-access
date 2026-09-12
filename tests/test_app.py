from __future__ import annotations

from typing import Protocol, cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from xcia.app import create_app
from xcia.config import RuntimeEnvironment, XciaSettings


class _Response(Protocol):
    status_code: int

    def json(self) -> object: ...


class _Client(Protocol):
    def get(self, url: str) -> _Response: ...


def test_service_boots_with_valid_configuration(settings: XciaSettings) -> None:
    app = create_app(settings)
    assert app.title == "XafPay XCIA"


def test_service_fails_closed_when_required_trust_config_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("XCIA_ENVIRONMENT", "XCIA_ISSUER", "XCIA_AUDIENCE", "XCIA_TRUSTED_ORIGINS"):
        monkeypatch.delenv(name, raising=False)

    try:
        create_app()
    except ValidationError:
        pass
    else:
        raise AssertionError("service must fail closed when required trust config is absent")


def test_health_live(settings: XciaSettings) -> None:
    client = cast(_Client, TestClient(create_app(settings)))
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live", "environment": "test"}


def test_health_ready(settings: XciaSettings) -> None:
    client = cast(_Client, TestClient(create_app(settings)))
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "environment": "test"}


def test_environment_specific_issuer_is_required() -> None:
    try:
        XciaSettings(
            environment=RuntimeEnvironment.TEST,
            issuer="urn:xafpay:customer-auth:production",
            audience="urn:xafpay:wallet-api:test",
            trusted_origins=("https://wallet.test",),
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("cross-environment issuer must be rejected")
