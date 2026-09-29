from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from tests.test_xcia3_authentication import make_service
from xcia.app import create_app
from xcia.config import XciaSettings
from xcia.persistence import XciaDatabase


class _FakeWalletHandoff:
    def issue(self, **_: object) -> SimpleNamespace:
        now = datetime.now(UTC)
        return SimpleNamespace(
            auth_completion_id="ac_test_completion_00000001",
            handoff_code="A" * 43,
            handoff_expires_at=now + timedelta(seconds=60),
        )


def test_bff_requires_exact_origin_and_csrf(database: XciaDatabase, settings: XciaSettings) -> None:
    service, _ = make_service(database, settings)
    client = TestClient(
        create_app(
            settings,
            authentication=service,
            wallet_session_handoff=_FakeWalletHandoff(),  # type: ignore[arg-type]
        )
    )
    payload = {"phone": "+2348012345678"}
    assert client.post("/bff/auth/enrollment/start", json=payload).status_code == 403
    assert (
        client.post(
            "/bff/auth/enrollment/start",
            json=payload,
            headers={"origin": "https://attacker.test", "x-xcia-csrf": "required"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/bff/auth/enrollment/start",
            json=payload,
            headers={"origin": "https://wallet.test"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/bff/auth/enrollment/start",
            json=payload,
            headers={"origin": "https://wallet.test", "x-xcia-csrf": "invalid"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/bff/auth/enrollment/start",
            json=payload,
            headers={"origin": "https://wallet.test", "x-xcia-csrf": "required"},
        ).status_code
        == 200
    )


def test_bff_sets_only_opaque_host_cookie(database: XciaDatabase, settings: XciaSettings) -> None:
    service, provider = make_service(database, settings)
    client = TestClient(
        create_app(
            settings,
            authentication=service,
            wallet_session_handoff=_FakeWalletHandoff(),  # type: ignore[arg-type]
        )
    )
    headers = {"origin": "https://wallet.test", "x-xcia-csrf": "required"}
    start = client.post(
        "/bff/auth/enrollment/start",
        json={"phone": "+2348012345678"},
        headers=headers,
    )
    challenge = start.json()["challenge_id"]
    proof = provider.expected_proof(challenge)
    verify = client.post(
        "/bff/auth/phone/verify",
        json={
            "phone": "+2348012345678",
            "challenge_id": challenge,
            "proof": proof,
        },
        headers=headers,
    )
    assert verify.status_code == 200
    complete = client.post(
        "/bff/auth/enrollment/complete",
        json={
            "phone": "+2348012345678",
            "challenge_id": challenge,
            "proof": proof,
            "pin": "123456",
            "sender_jkt": "thumbprint_01JTESTKEY000000001",
            "device_id": "test-device-one",
        },
        headers=headers,
    )
    cookie = complete.headers["set-cookie"]
    body = complete.json()
    assert body["status"] == "authenticated"
    assert body["auth_completion_id"] == "ac_test_completion_00000001"
    assert body["handoff_code"] == "A" * 43
    assert "handoff_expires_at" in body
    assert "authoritative_xcia_idle_expires_at" not in body
    assert "authoritative_xcia_absolute_expires_at" not in body
    assert settings.session_cookie_name in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "Path=/" in cookie
    assert "123456" not in complete.text
    assert "access_token" not in complete.text
