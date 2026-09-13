from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from xcia.app import create_app
from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.crypto import StagingEs256KeyProvider
from xcia.domain import SigningKeyState
from xcia.persistence import XciaDatabase
from xcia.services import DurableReadinessProbe


class _Response(Protocol):
    status_code: int

    def json(self) -> object: ...


class _Client(Protocol):
    def get(self, url: str) -> _Response: ...


def _staging_settings() -> XciaSettings:
    return XciaSettings(
        environment=RuntimeEnvironment.STAGING,
        issuer="urn:xafpay:customer-auth:staging",
        audience="urn:xafpay:wallet-api:staging",
        trusted_origins=("https://wallet.staging.example",),
    )



def test_database_runtime_rejects_non_postgresql() -> None:
    with pytest.raises(ValueError):
        XciaDatabase("sqlite+pysqlite:///:memory:")


def test_staging_readiness_fails_closed_without_dependencies() -> None:
    client = cast(_Client, TestClient(create_app(_staging_settings())))
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 503


def test_readiness_passes_with_database_schema_and_signing_authority(
    database: XciaDatabase,
) -> None:
    provider = StagingEs256KeyProvider(
        database,
        issuer="urn:xafpay:customer-auth:staging",
        environment="staging",
        injected_private_keys={},
    )
    provider.register_key(
        kid="kid-ready-0001",
        private_key=ec.generate_private_key(ec.SECP256R1()),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    probe = DurableReadinessProbe(
        database=database,
        signing_keys=provider,
        jwks=provider,
        expected_revision="xcia3_0001",
    )
    client = cast(_Client, TestClient(create_app(_staging_settings(), probe)))
    response = client.get("/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "environment": "staging"}


def test_readiness_fails_closed_without_active_signing_authority(
    database: XciaDatabase,
) -> None:
    provider = StagingEs256KeyProvider(
        database,
        issuer="urn:xafpay:customer-auth:staging",
        environment="staging",
        injected_private_keys={},
    )
    probe = DurableReadinessProbe(
        database=database,
        signing_keys=provider,
        jwks=provider,
        expected_revision="xcia2_0001",
    )
    assert probe.is_ready() is False
def test_readiness_fails_closed_when_schema_revision_is_not_current(
    database: XciaDatabase,
) -> None:
    provider = StagingEs256KeyProvider(
        database,
        issuer="urn:xafpay:customer-auth:staging",
        environment="staging",
        injected_private_keys={},
    )
    provider.register_key(
        kid="kid-ready-0002",
        private_key=ec.generate_private_key(ec.SECP256R1()),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    probe = DurableReadinessProbe(
        database=database,
        signing_keys=provider,
        jwks=provider,
        expected_revision="not-current",
    )
    assert probe.is_ready() is False
