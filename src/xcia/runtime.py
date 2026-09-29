from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from sqlalchemy import select

from xcia.adapters import (
    DurableAuthenticationControlStore,
    DurablePinCredentialStore,
    DurableSessionStore,
    DurableSubjectStore,
    DurableWalletSessionHandoffStore,
    SecurityEventStore,
    compose_phone_verification_provider,
)
from xcia.adapters.postgres import DurablePhoneVerificationChallengeStore
from xcia.app import create_app
from xcia.config import RuntimeEnvironment, Xcia2RuntimeSettings, Xcia3RuntimeSettings, XciaSettings
from xcia.crypto import CredentialSecrets, StagingEs256KeyProvider
from xcia.domain import SigningKeyState
from xcia.persistence import XciaDatabase
from xcia.persistence.schema import SigningKeyRow
from xcia.services import (
    CustomerPinAuthenticationService,
    DurableAssertionIssuer,
    DurableReadinessProbe,
    JwksPresenter,
    WalletSessionHandoffService,
)

EXPECTED_REVISION = "xcia_phone_challenge_bind_0001"
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
    xcia3 = Xcia3RuntimeSettings()  # pyright: ignore[reportCallIssue]
    credential_secret_value = os.environ.get(xcia3.credential_secret_env)
    if credential_secret_value is None or not credential_secret_value.strip():
        raise ValueError("XCIA3 credential root secret is required")
    credential_secret = credential_secret_value.encode("utf-8")
    xcia3.validate_for_environment(settings.environment, credential_secret)
    credential_secrets = CredentialSecrets(credential_secret)
    phone_provider = compose_phone_verification_provider(
        settings=xcia3,
        environment=settings.environment,
        fake_secret=credential_secrets.derive("xcia3/staging-phone-proof"),
    )

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
    subjects = DurableSubjectStore(database)
    credentials = DurablePinCredentialStore(database)
    challenges = DurablePhoneVerificationChallengeStore(database)
    controls = DurableAuthenticationControlStore(database)
    events = SecurityEventStore(database)
    authentication = CustomerPinAuthenticationService(
        settings=settings,
        xcia3=xcia3,
        secrets=credential_secrets,
        phone_provider=phone_provider,
        subjects=subjects,
        sessions=sessions,
        credentials=credentials,
        challenges=challenges,
        controls=controls,
        events=events,
    )

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
        authentication=authentication,
        wallet_assertion_issuer=assertion_issuer,
        wallet_jwks=jwks_presenter,
        wallet_session_handoff=handoff_service,
    )
