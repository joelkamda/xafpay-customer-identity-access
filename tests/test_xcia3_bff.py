from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_xcia3_authentication import make_service
from xcia.app import create_app
from xcia.config import XciaSettings
from xcia.persistence import XciaDatabase


def test_bff_requires_exact_origin_and_csrf(database: XciaDatabase, settings: XciaSettings) -> None:
    service, _ = make_service(database, settings)
    client = TestClient(create_app(settings, authentication=service))
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


def test_bff_sets_only_opaque_host_cookie(database: XciaDatabase, settings: XciaSettings) -> None:
    service, provider = make_service(database, settings)
    client = TestClient(create_app(settings, authentication=service))
    headers = {"origin": "https://wallet.test", "x-xcia-csrf": "required"}
    start = client.post(
        "/bff/auth/enrollment/start",
        json={"phone": "+2348012345678"},
        headers=headers,
    )
    challenge = start.json()["challenge_id"]
    complete = client.post(
        "/bff/auth/enrollment/complete",
        json={
            "phone": "+2348012345678",
            "challenge_id": challenge,
            "proof": provider.expected_proof(challenge),
            "pin": "123456",
            "sender_jkt": "thumbprint_01JTESTKEY000000001",
            "device_id": "test-device-one",
        },
        headers=headers,
    )
    cookie = complete.headers["set-cookie"]
    assert complete.json() == {"status": "authenticated"}
    assert settings.session_cookie_name in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "Path=/" in cookie
    assert "123456" not in complete.text
    assert "access_token" not in complete.text
