from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from httpx import Response

from xcia.adapters import DurableSessionStore, DurableSubjectStore
from xcia.app import create_app
from xcia.config import XciaSettings
from xcia.crypto import StagingEs256KeyProvider
from xcia.domain import (
    RelyingPartyTrustPolicy,
    SigningKeyState,
    TrustedAuthenticationContext,
)
from xcia.persistence import XciaDatabase
from xcia.relying_party import WalletRelyingPartyProfile
from xcia.services import DurableAssertionIssuer, JwksPresenter

ORIGIN = "https://wallet.test"
HEADERS = {"origin": ORIGIN, "x-xcia-csrf": "required"}
SENDER_JKT = "senderthumbprint_fl1a_0123456789abcdef"


@dataclass(slots=True)
class WalletRpHarness:
    client: TestClient
    provider: StagingEs256KeyProvider
    sessions: DurableSessionStore
    settings: XciaSettings
    sid: str
    sub: str
    sender_jkt: str


def _build_harness(
    database: XciaDatabase,
    settings: XciaSettings,
    *,
    session_created_at: datetime | None = None,
) -> WalletRpHarness:
    created_at = session_created_at if session_created_at is not None else datetime.now(UTC)
    subject = DurableSubjectStore(database).create_or_lookup(
        authentication_handle="authref_fl1a_11223344556677889900aabbccddeeff",
        relying_party=settings.audience,
        environment=settings.environment.value,
        now=created_at,
    )
    sessions = DurableSessionStore(database)
    snapshot = sessions.create_authenticated_session(
        TrustedAuthenticationContext(
            subject=subject,
            auth_time=created_at,
            sender_jkt=SENDER_JKT,
            trust_source="fl1a-wallet-rp-http-test",
        ),
        now=created_at,
    )
    provider = StagingEs256KeyProvider(
        database,
        issuer=settings.issuer,
        environment=settings.environment.value,
        injected_private_keys={},
    )
    provider.register_key(
        kid="kid-fl1a-wallet-rp-0001",
        private_key=ec.generate_private_key(ec.SECP256R1()),
        state=SigningKeyState.ACTIVE_SIGNING,
        not_before=datetime.now(UTC) - timedelta(seconds=1),
    )
    issuer = DurableAssertionIssuer(settings, sessions, provider)
    app = create_app(
        settings,
        wallet_assertion_issuer=issuer,
        wallet_jwks=JwksPresenter(provider),
    )
    client = TestClient(app, base_url=ORIGIN)
    client.cookies.set(
        settings.session_cookie_name,
        snapshot.sid,
        domain="wallet.test",
        path="/",
    )
    return WalletRpHarness(
        client=client,
        provider=provider,
        sessions=sessions,
        settings=settings,
        sid=snapshot.sid,
        sub=snapshot.sub,
        sender_jkt=SENDER_JKT,
    )


def _post_assertion(
    harness: WalletRpHarness,
    *,
    sender_jkt: str | None = None,
) -> Response:
    return harness.client.post(
        "/bff/relying-parties/wallet/assertion",
        json={"sender_jkt": sender_jkt if sender_jkt is not None else harness.sender_jkt},
        headers=HEADERS,
    )


def _claims(harness: WalletRpHarness, token: str):
    return harness.provider.verify(
        token,
        RelyingPartyTrustPolicy(
            issuer=harness.settings.issuer,
            audience=harness.settings.audience,
        ),
    )


def test_active_session_assertion_passes(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    assert response.status_code == 200
    assert set(response.json()) == {"assertion", "token_type", "expires_in"}
    assert response.json()["token_type"] == "DPoP"
    assert response.json()["expires_in"] == 300


def test_missing_session_is_denied(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    harness.client.cookies.clear()
    response = _post_assertion(harness)
    assert response.status_code == 401


def test_revoked_session_is_denied(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    harness.sessions.revoke_session(harness.sid)
    response = _post_assertion(harness)
    assert response.status_code == 401


def test_expired_session_is_denied(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(
        database,
        settings,
        session_created_at=datetime.now(UTC) - timedelta(minutes=16),
    )
    response = _post_assertion(harness)
    assert response.status_code == 401


def test_sender_jkt_is_required(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = harness.client.post(
        "/bff/relying-parties/wallet/assertion",
        json={},
        headers=HEADERS,
    )
    assert response.status_code == 422


def test_sender_jkt_mismatch_is_denied(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(
        harness,
        sender_jkt="different_sender_thumbprint_0123456789",
    )
    assert response.status_code == 403


def test_exact_issuer_is_preserved(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    claims = _claims(harness, response.json()["assertion"])
    assert claims.iss == settings.issuer


def test_exact_wallet_audience_is_preserved(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    claims = _claims(harness, response.json()["assertion"])
    assert claims.aud == settings.audience
    assert claims.aud == f"urn:xafpay:wallet-api:{settings.environment.value}"


def test_caller_cannot_override_audience(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = harness.client.post(
        "/bff/relying-parties/wallet/assertion",
        json={
            "sender_jkt": harness.sender_jkt,
            "audience": "urn:xafpay:wallet-api:attacker",
        },
        headers=HEADERS,
    )
    assert response.status_code == 422


def test_caller_cannot_supply_subject(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = harness.client.post(
        "/bff/relying-parties/wallet/assertion",
        json={"sender_jkt": harness.sender_jkt, "sub": "sub_attacker_supplied_00000001"},
        headers=HEADERS,
    )
    assert response.status_code == 422


def test_pairwise_subject_is_preserved(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    claims = _claims(harness, response.json()["assertion"])
    assert claims.sub == harness.sub
    assert claims.sub.startswith("sub_")


def test_economic_claims_are_absent(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    payload = jwt.decode(
        response.json()["assertion"],
        options={"verify_signature": False, "verify_aud": False},
    )
    forbidden = {
        "phone",
        "email",
        "name",
        "wallet_id",
        "wallet_role",
        "wallet_permission",
        "balance",
        "transfer_authority",
        "core_account",
        "economic_account",
    }
    assert forbidden.isdisjoint(payload)


def test_assertion_expiry_is_exactly_300_seconds(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = _post_assertion(harness)
    claims = _claims(harness, response.json()["assertion"])
    assert claims.exp - claims.iat == 300


def test_new_jti_is_minted_per_assertion(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    first = _claims(harness, _post_assertion(harness).json()["assertion"])
    second = _claims(harness, _post_assertion(harness).json()["assertion"])
    assert first.jti != second.jti


def test_jwks_contains_public_keys_only(
    database: XciaDatabase,
    settings: XciaSettings,
) -> None:
    harness = _build_harness(database, settings)
    response = harness.client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    document = response.json()
    assert set(document) == {"keys"}
    assert len(document["keys"]) == 1
    key = document["keys"][0]
    assert {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.isdisjoint(key)
    assert key["alg"] == "ES256"


class _UnsafeJwksProvider:
    def public_jwks(self) -> Sequence[Mapping[str, object]]:
        return (
            {
                "kty": "EC",
                "kid": "unsafe-kid",
                "alg": "ES256",
                "d": "private-material-must-not-leak",
            },
        )


def test_private_jwk_fields_are_rejected(settings: XciaSettings) -> None:
    app = create_app(
        settings,
        wallet_jwks=JwksPresenter(_UnsafeJwksProvider()),
    )
    response = TestClient(app, base_url=ORIGIN).get("/.well-known/jwks.json")
    assert response.status_code == 503
    assert "private-material-must-not-leak" not in response.text


def test_wallet_relying_party_profile_is_exact(settings: XciaSettings) -> None:
    profile = WalletRelyingPartyProfile.from_settings(settings)
    assert profile.relying_party == "WALLET_API"
    assert profile.issuer == settings.issuer
    assert profile.audience == f"urn:xafpay:wallet-api:{settings.environment.value}"
    assert profile.environment == settings.environment.value
    assert profile.assertion_lifetime_seconds == 300
    assert profile.sender_constraint_required is True


def test_existing_auth_endpoint_regression_is_preserved(settings: XciaSettings) -> None:
    client = TestClient(create_app(settings), base_url=ORIGIN)
    response = client.post(
        "/bff/auth/enrollment/start",
        json={"phone": "+237600000000"},
        headers=HEADERS,
    )
    assert response.status_code == 503
