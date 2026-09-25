from __future__ import annotations

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from sqlalchemy import select

from xcia.adapters import DurableSessionStore, DurableWalletSessionHandoffStore
from xcia.app import create_app
from xcia.config import RuntimeEnvironment, Xcia2RuntimeSettings, XciaSettings
from xcia.crypto import StagingEs256KeyProvider
from xcia.domain import SigningKeyState
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import SigningKeyRow
from xcia.services import (
    DurableAssertionIssuer,
    DurableReadinessProbe,
    JwksPresenter,
    WalletSessionHandoffService,
)

EXPECTED_REVISION = "fl1f_0001_wallet_session_handoff"
def _loaded_private_key(
    provider: StagingEs256KeyProvider,
    kid: str,
) -> ec.EllipticCurvePrivateKey:
    private_keys: dict[str, ec.EllipticCurvePrivateKey] = (
        provider._private_keys  # pyright: ignore[reportPrivateUsage]
    )
    private_key = private_keys.get(kid)
    if private_key is None:
        raise ValueError("configured signing private key is unavailable")
    return private_key


def _qualify_or_bootstrap_signing_authority(
    *,
    settings: XciaSettings,
    xcia2: Xcia2RuntimeSettings,
    database: XciaDatabase,
    provider: StagingEs256KeyProvider,
) -> None:
    kid = xcia2.signing_key_kid
    with database.session() as session:
        active_rows = list(
            session.scalars(
                select(SigningKeyRow).where(
                    SigningKeyRow.environment == settings.environment.value,
                    SigningKeyRow.issuer == settings.issuer,
                    SigningKeyRow.state == SigningKeyState.ACTIVE_SIGNING.value,
                )
            )
        )
        configured_row = session.get(SigningKeyRow, kid)

    if len(active_rows) > 1:
        raise ValueError("multiple active staging signing keys are forbidden")

    if active_rows:
        active_row = active_rows[0]
        if active_row.kid != kid:
            raise ValueError("active staging signing key does not match configured kid")
        reference = provider.active_signing_key()
        if reference.kid != kid:
            raise ValueError("active staging signing authority does not match configured kid")
        return

    if configured_row is not None:
        raise ValueError("configured kid already exists in an incompatible signing state")

    provider.register_key(
        kid=kid,
        private_key=_loaded_private_key(provider, kid),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC),
    )
    reference = provider.active_signing_key()
    if reference.kid != kid:
        raise ValueError("first-time staging signing key registration failed closed")


def create_staging_app() -> FastAPI:
    settings = XciaSettings.from_environment()
    if settings.environment is not RuntimeEnvironment.STAGING:
        raise ValueError("create_staging_app requires XCIA_ENVIRONMENT=staging")

    xcia2 = Xcia2RuntimeSettings()  # pyright: ignore[reportCallIssue]
    database = XciaDatabase(xcia2.database_url)

    signing_provider = StagingEs256KeyProvider.from_environment(
        database,
        issuer=settings.issuer,
        environment=settings.environment.value,
        kid=xcia2.signing_key_kid,
        private_key_environment_variable=xcia2.signing_private_key_env,
    )
    _qualify_or_bootstrap_signing_authority(
        settings=settings,
        xcia2=xcia2,
        database=database,
        provider=signing_provider,
    )

    sessions = DurableSessionStore(database)
    assertion_issuer = DurableAssertionIssuer(
        settings,
        sessions,
        signing_provider,
    )
    jwks_presenter = JwksPresenter(signing_provider)
    handoff_store = DurableWalletSessionHandoffStore(database)
    handoff_service = WalletSessionHandoffService.from_settings(
        settings,
        handoff_store,
    )
    readiness = DurableReadinessProbe(
        database=database,
        signing_keys=signing_provider,
        jwks=signing_provider,
        expected_revision=EXPECTED_REVISION,
    )

    return create_app(
        settings=settings,
        readiness=readiness,
        wallet_assertion_issuer=assertion_issuer,
        wallet_jwks=jwks_presenter,
        wallet_session_handoff=handoff_service,
    )
