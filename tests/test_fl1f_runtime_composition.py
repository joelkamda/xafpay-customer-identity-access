from __future__ import annotations

import hashlib
from contextlib import AbstractContextManager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI

from xcia import runtime
from xcia.config import RuntimeEnvironment, Xcia2RuntimeSettings, XciaSettings

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SOURCE = ROOT / "src/xcia/runtime.py"
APP_SOURCE = ROOT / "src/xcia/app.py"
ACCEPTED_APP_SHA256 = "ac280658cf16e47136aaaaeb0c77a4bce98fdd50026f2815cf9a3a4fd717e4bd"
TEST_ORIGIN = "https://wallet-web.staging.test"
TEST_KID = "xcia-test-signing-key-01"
TEST_KEY_ENV = "XCIA_R2_TEST_SIGNING_PRIVATE_KEY"


def _set_staging_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_handoff_token: bool = True,
) -> None:
    values = {
        "XCIA_ENVIRONMENT": "staging",
        "XCIA_ISSUER": "urn:xafpay:customer-auth:staging",
        "XCIA_AUDIENCE": "urn:xafpay:wallet-api:staging",
        "XCIA_TRUSTED_ORIGINS": f'["{TEST_ORIGIN}"]',
        "XCIA2_DATABASE_URL": "postgresql+psycopg://xcia@localhost/xcia_test",
        "XCIA2_SIGNING_KEY_KID": TEST_KID,
        "XCIA2_SIGNING_PRIVATE_KEY_ENV": TEST_KEY_ENV,
        TEST_KEY_ENV: "test-private-key-placeholder",
    }
    if include_handoff_token:
        values["XCIA_WALLET_WEB_HANDOFF_SERVICE_TOKEN"] = "T" * 32
    else:
        monkeypatch.delenv("XCIA_WALLET_WEB_HANDOFF_SERVICE_TOKEN", raising=False)
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def _install_composition_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    patch_handoff_service: bool = True,
) -> dict[str, Any]:
    capture: dict[str, Any] = {}

    def database_factory(url: str) -> object:
        database = SimpleNamespace(url=url)
        capture["database"] = database
        return database
    class ProviderFactory:
        @classmethod
        def from_environment(cls, database: object, **kwargs: object) -> object:
            provider = SimpleNamespace()
            capture["provider"] = provider
            capture["provider_database"] = database
            capture["provider_kwargs"] = kwargs
            return provider

    def bootstrap(**kwargs: object) -> None:
        capture["bootstrap"] = kwargs

    def session_store(database: object) -> object:
        store = SimpleNamespace()
        capture["session_store"] = store
        capture["session_store_database"] = database
        return store

    def assertion_issuer(
        settings: XciaSettings,
        sessions: object,
        signer: object,
    ) -> object:
        issuer = SimpleNamespace(settings=settings)
        capture["assertion_issuer"] = issuer
        capture["issuer_settings"] = settings
        capture["issuer_sessions"] = sessions
        capture["issuer_signer"] = signer
        return issuer
    def jwks_presenter(provider: object) -> object:
        presenter = SimpleNamespace()
        capture["jwks"] = presenter
        capture["jwks_provider"] = provider
        return presenter

    def handoff_store(database: object) -> object:
        store = SimpleNamespace()
        capture["handoff_store"] = store
        capture["handoff_store_database"] = database
        return store

    class HandoffServiceFactory:
        @classmethod
        def from_settings(cls, settings: XciaSettings, store: object) -> object:
            service = SimpleNamespace()
            capture["handoff_service"] = service
            capture["handoff_settings"] = settings
            capture["handoff_store_arg"] = store
            return service

    def readiness_probe(**kwargs: object) -> object:
        probe = SimpleNamespace()
        capture["readiness"] = probe
        capture["readiness_kwargs"] = kwargs
        return probe

    def app_factory(**kwargs: object) -> FastAPI:
        capture["create_app_kwargs"] = kwargs
        return FastAPI()
    monkeypatch.setattr(runtime, "XciaDatabase", database_factory)
    monkeypatch.setattr(runtime, "StagingEs256KeyProvider", ProviderFactory)
    monkeypatch.setattr(runtime, "_qualify_or_bootstrap_signing_authority", bootstrap)
    monkeypatch.setattr(runtime, "DurableSessionStore", session_store)
    monkeypatch.setattr(runtime, "DurableAssertionIssuer", assertion_issuer)
    monkeypatch.setattr(runtime, "JwksPresenter", jwks_presenter)
    monkeypatch.setattr(runtime, "DurableWalletSessionHandoffStore", handoff_store)
    if patch_handoff_service:
        monkeypatch.setattr(runtime, "WalletSessionHandoffService", HandoffServiceFactory)
    monkeypatch.setattr(runtime, "DurableReadinessProbe", readiness_probe)
    monkeypatch.setattr(runtime, "create_app", app_factory)
    return capture


def _compose(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    _set_staging_env(monkeypatch)
    capture = _install_composition_fakes(monkeypatch)
    app = runtime.create_staging_app()
    assert isinstance(app, FastAPI)
    return capture


class _FakeKeySession(AbstractContextManager["_FakeKeySession"]):
    def __init__(
        self,
        active_rows: list[SimpleNamespace],
        configured_row: SimpleNamespace | None,
    ) -> None:
        self.active_rows = active_rows
        self.configured_row = configured_row

    def __enter__(self) -> _FakeKeySession:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def scalars(self, _statement: object) -> list[SimpleNamespace]:
        return self.active_rows

    def get(self, _model: object, _kid: str) -> SimpleNamespace | None:
        return self.configured_row


class _FakeKeyDatabase:
    def __init__(
        self,
        active_rows: list[SimpleNamespace],
        configured_row: SimpleNamespace | None = None,
    ) -> None:
        self.active_rows = active_rows
        self.configured_row = configured_row

    def session(self) -> _FakeKeySession:
        return _FakeKeySession(self.active_rows, self.configured_row)


class _FakeKeyProvider:
    def __init__(self, configured_kid: str, active_kid: str | None) -> None:
        self._private_keys = {configured_kid: object()}
        self.active_kid = active_kid
        self.register_calls: list[dict[str, object]] = []

    def active_signing_key(self) -> SimpleNamespace:
        if self.active_kid is None:
            raise ValueError("no active key")
        return SimpleNamespace(kid=self.active_kid)

    def register_key(self, **kwargs: object) -> None:
        self.register_calls.append(kwargs)
        self.active_kid = str(kwargs["kid"])


def _bootstrap_settings() -> tuple[XciaSettings, Xcia2RuntimeSettings]:
    settings = XciaSettings(
        environment=RuntimeEnvironment.STAGING,
        issuer="urn:xafpay:customer-auth:staging",
        audience="urn:xafpay:wallet-api:staging",
        trusted_origins=(TEST_ORIGIN,),
        wallet_web_handoff_service_token="T" * 32,
    )
    xcia2 = Xcia2RuntimeSettings(
        database_url="postgresql+psycopg://xcia@localhost/xcia_test",
        signing_key_kid=TEST_KID,
        signing_private_key_env=TEST_KEY_ENV,
    )
    return settings, xcia2


def _runtime_text() -> str:
    return RUNTIME_SOURCE.read_text(encoding="utf-8")
def test_01_create_staging_app_rejects_non_staging_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for environment in ("development", "test", "production"):
        _set_staging_env(monkeypatch)
        monkeypatch.setenv("XCIA_ENVIRONMENT", environment)
        monkeypatch.setenv("XCIA_ISSUER", f"urn:xafpay:customer-auth:{environment}")
        monkeypatch.setenv("XCIA_AUDIENCE", f"urn:xafpay:wallet-api:{environment}")
        with pytest.raises(ValueError, match="requires XCIA_ENVIRONMENT=staging"):
            runtime.create_staging_app()


def test_02_valid_staging_configuration_constructs_xcia_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["database"].url == "postgresql+psycopg://xcia@localhost/xcia_test"


def test_03_valid_staging_configuration_constructs_signing_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["provider_database"] is capture["database"]
    assert capture["provider_kwargs"]["kid"] == TEST_KID


def test_04_valid_staging_configuration_constructs_durable_session_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["session_store_database"] is capture["database"]
def test_05_valid_staging_configuration_constructs_assertion_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["assertion_issuer"] is capture["create_app_kwargs"]["wallet_assertion_issuer"]


def test_06_valid_staging_configuration_constructs_jwks_presenter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["jwks"] is capture["create_app_kwargs"]["wallet_jwks"]


def test_07_valid_staging_configuration_constructs_handoff_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["handoff_store_database"] is capture["database"]


def test_08_valid_staging_configuration_constructs_handoff_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["handoff_service"] is capture["create_app_kwargs"]["wallet_session_handoff"]


def test_09_valid_staging_configuration_constructs_readiness_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["readiness"] is capture["create_app_kwargs"]["readiness"]
def test_10_readiness_expected_revision_is_fl1f(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["readiness_kwargs"]["expected_revision"] == runtime.EXPECTED_REVISION
    assert runtime.EXPECTED_REVISION == "fl1f_0001_wallet_session_handoff"
    assert len(runtime.EXPECTED_REVISION) <= 32


def test_11_create_app_receives_non_null_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["create_app_kwargs"]["readiness"] is not None


def test_12_create_app_receives_non_null_wallet_assertion_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["create_app_kwargs"]["wallet_assertion_issuer"] is not None


def test_13_create_app_receives_non_null_wallet_jwks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["create_app_kwargs"]["wallet_jwks"] is not None


def test_14_create_app_receives_non_null_wallet_session_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["create_app_kwargs"]["wallet_session_handoff"] is not None
def test_15_missing_database_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch)
    monkeypatch.delenv("XCIA2_DATABASE_URL")
    with pytest.raises(ValueError):
        runtime.create_staging_app()


def test_16_invalid_database_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch)
    monkeypatch.setenv("XCIA2_DATABASE_URL", "sqlite+pysqlite:///:memory:")
    with pytest.raises(ValueError):
        runtime.create_staging_app()


def test_17_missing_signing_key_kid_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch)
    monkeypatch.delenv("XCIA2_SIGNING_KEY_KID")
    with pytest.raises(ValueError):
        runtime.create_staging_app()


def test_18_missing_signing_private_key_env_name_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch)
    monkeypatch.delenv("XCIA2_SIGNING_PRIVATE_KEY_ENV")
    with pytest.raises(ValueError):
        runtime.create_staging_app()
def test_19_missing_or_invalid_private_key_material_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch)

    def fake_database(_url: str) -> object:
        return object()

    monkeypatch.setattr(runtime, "XciaDatabase", fake_database)
    monkeypatch.delenv(TEST_KEY_ENV)
    with pytest.raises(ValueError):
        runtime.create_staging_app()

    monkeypatch.setenv(TEST_KEY_ENV, "not-a-private-key")
    with pytest.raises(ValueError):
        runtime.create_staging_app()


def test_20_missing_wallet_web_handoff_service_token_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_staging_env(monkeypatch, include_handoff_token=False)
    _install_composition_fakes(monkeypatch, patch_handoff_service=False)
    with pytest.raises(ValueError, match="handoff service token is not configured"):
        runtime.create_staging_app()


def test_21_existing_active_key_with_configured_kid_is_reused() -> None:
    settings, xcia2 = _bootstrap_settings()
    row = SimpleNamespace(kid=TEST_KID)
    database = _FakeKeyDatabase([row], configured_row=row)
    provider = _FakeKeyProvider(TEST_KID, TEST_KID)
    runtime._qualify_or_bootstrap_signing_authority(  # pyright: ignore[reportPrivateUsage]
        settings=settings, xcia2=xcia2, database=database, provider=provider  # type: ignore[arg-type]
    )
    assert provider.register_calls == []
def test_22_no_active_key_supports_one_first_time_registration() -> None:
    settings, xcia2 = _bootstrap_settings()
    database = _FakeKeyDatabase([])
    provider = _FakeKeyProvider(TEST_KID, None)
    runtime._qualify_or_bootstrap_signing_authority(  # pyright: ignore[reportPrivateUsage]
        settings=settings, xcia2=xcia2, database=database, provider=provider  # type: ignore[arg-type]
    )
    assert len(provider.register_calls) == 1
    assert provider.register_calls[0]["kid"] == TEST_KID
    assert provider.active_kid == TEST_KID


def test_23_different_active_key_from_configured_kid_fails_closed() -> None:
    settings, xcia2 = _bootstrap_settings()
    database = _FakeKeyDatabase([SimpleNamespace(kid="other-active-key")])
    provider = _FakeKeyProvider(TEST_KID, "other-active-key")
    with pytest.raises(ValueError, match="does not match configured kid"):
        runtime._qualify_or_bootstrap_signing_authority(  # pyright: ignore[reportPrivateUsage]
            settings=settings, xcia2=xcia2, database=database, provider=provider  # type: ignore[arg-type]
        )
    assert provider.register_calls == []


def test_24_conflicting_existing_configured_kid_fails_closed() -> None:
    settings, xcia2 = _bootstrap_settings()
    configured = SimpleNamespace(kid=TEST_KID)
    database = _FakeKeyDatabase([], configured_row=configured)
    provider = _FakeKeyProvider(TEST_KID, None)
    with pytest.raises(ValueError, match="incompatible signing state"):
        runtime._qualify_or_bootstrap_signing_authority(  # pyright: ignore[reportPrivateUsage]
            settings=settings, xcia2=xcia2, database=database, provider=provider  # type: ignore[arg-type]
        )
    assert provider.register_calls == []


def test_25_no_automatic_key_rotation_or_demotion() -> None:
    settings, xcia2 = _bootstrap_settings()
    database = _FakeKeyDatabase(
        [SimpleNamespace(kid=TEST_KID), SimpleNamespace(kid="second-active-key")]
    )
    provider = _FakeKeyProvider(TEST_KID, TEST_KID)
    with pytest.raises(ValueError, match="multiple active"):
        runtime._qualify_or_bootstrap_signing_authority(  # pyright: ignore[reportPrivateUsage]
            settings=settings, xcia2=xcia2, database=database, provider=provider  # type: ignore[arg-type]
        )
    source = _runtime_text()
    assert provider.register_calls == []
    assert ".activate_key(" not in source
    assert ".retire_key(" not in source


def test_26_jwks_presenter_uses_same_composed_signing_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["jwks_provider"] is capture["provider"]
def test_27_assertion_issuer_uses_same_durable_session_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["issuer_sessions"] is capture["session_store"]


def test_28_assertion_issuer_uses_same_signing_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["issuer_signer"] is capture["provider"]


def test_29_handoff_service_uses_durable_handoff_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    assert capture["handoff_store_arg"] is capture["handoff_store"]


def test_30_trusted_origin_comes_only_from_xcia_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _compose(monkeypatch)
    settings = capture["handoff_settings"]
    assert settings is capture["create_app_kwargs"]["settings"]
    assert settings.trusted_origins == (TEST_ORIGIN,)


def test_31_runtime_contains_no_legacy_app_local_netlify_origin() -> None:
    assert "app-local-xafpay.netlify.app" not in _runtime_text()
def test_32_runtime_contains_no_legacy_app_local_custom_origin() -> None:
    assert "app.local.xafpay.com" not in _runtime_text()


def test_33_runtime_does_not_invent_new_wallet_web_origin() -> None:
    assert "https://" not in _runtime_text()


def test_34_startup_creates_no_identity() -> None:
    source = _runtime_text()
    assert "DurableSubjectStore" not in source
    assert "CustomerPinCredential" not in source


def test_35_startup_creates_no_session() -> None:
    assert ".create_session(" not in _runtime_text()


def test_36_startup_creates_no_handoff_record() -> None:
    source = _runtime_text()
    assert "handoff_service.issue(" not in source
    assert "handoff_store.issue(" not in source


def test_37_startup_issues_no_wallet_assertion() -> None:
    assert "assertion_issuer.issue(" not in _runtime_text()


def test_38_startup_calls_no_infobip_provider() -> None:
    source = _runtime_text()
    assert "Infobip" not in source
    assert "compose_phone_verification_provider" not in source
def test_39_existing_xcia_app_source_remains_unchanged() -> None:
    digest = hashlib.sha256(APP_SOURCE.read_bytes()).hexdigest()
    assert digest == ACCEPTED_APP_SHA256
