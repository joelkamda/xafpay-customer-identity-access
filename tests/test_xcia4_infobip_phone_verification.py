from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast

import pytest

from xcia.adapters import InfobipHttpResponse, InfobipPhoneVerificationAdapter


@dataclass
class ScriptedTransport:
    responses: list[InfobipHttpResponse | Exception]
    requests: list[tuple[str, dict[str, str], dict[str, object], int]] = field(
        default_factory=lambda: cast(
            list[tuple[str, dict[str, str], dict[str, object], int]],
            [],
        )
    )

    def post(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> InfobipHttpResponse:
        self.requests.append((url, headers, json.loads(body), timeout_seconds))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def response(status: int, body: object) -> InfobipHttpResponse:
    return InfobipHttpResponse(status, json.dumps(body).encode("utf-8"))


def adapter(transport: ScriptedTransport) -> InfobipPhoneVerificationAdapter:
    return InfobipPhoneVerificationAdapter(
        base_url="https://api.infobip.test",
        application_id="application-test",
        message_id="message-test",
        sender_id="XafPay",
        api_key="test-not-a-real-infobip-key",
        request_timeout_seconds=7,
        challenge_ttl_seconds=300,
        transport=transport,
    )


def test_begin_maps_only_required_sms_2fa_fields_and_pin_id() -> None:
    transport = ScriptedTransport([response(200, {"pinId": "p" * 16})])
    challenge = adapter(transport).begin("+237612345678", now=datetime.now(UTC))
    url, headers, body, timeout = transport.requests[0]
    assert url == "https://api.infobip.test/2fa/2/pin"
    assert headers["Authorization"] == "App test-not-a-real-infobip-key"
    assert body == {
        "applicationId": "application-test",
        "messageId": "message-test",
        "from": "XafPay",
        "to": "+237612345678",
    }
    assert timeout == 7
    assert challenge.challenge_id == "p" * 16


@pytest.mark.parametrize(
    "body",
    [{}, {"pinId": 123}, {"pinId": "short"}, {"pinId": "p" * 256}, []],
)
def test_begin_fails_closed_for_invalid_pin_id(body: object) -> None:
    transport = ScriptedTransport([response(200, body)])
    with pytest.raises(ValueError, match="provider"):
        adapter(transport).begin("+237612345678", now=datetime.now(UTC))


def test_verify_maps_pin_and_requires_explicit_verified_true() -> None:
    transport = ScriptedTransport([response(200, {"verified": True})])
    assert adapter(transport).verify("p" * 16, "1234", now=datetime.now(UTC))
    url, _, body, _ = transport.requests[0]
    assert url == f"https://api.infobip.test/2fa/2/pin/{'p' * 16}/verify"
    assert body == {"pin": "1234"}


@pytest.mark.parametrize(
    "provider_response",
    [
        response(200, {"verified": False}),
        response(200, {"verified": "true"}),
        response(200, {}),
        response(401, {"verified": True}),
        response(403, {"verified": True}),
        response(429, {"verified": True}),
        response(500, {"verified": True}),
        InfobipHttpResponse(200, b"not-json"),
        RuntimeError("timeout"),
    ],
)
def test_verify_fails_closed_for_denied_or_unavailable_provider_response(
    provider_response: InfobipHttpResponse | Exception,
) -> None:
    transport = ScriptedTransport([provider_response])
    assert not adapter(transport).verify("p" * 16, "wrong-or-expired", now=datetime.now(UTC))
