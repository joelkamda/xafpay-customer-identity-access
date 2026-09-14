from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from xcia.adapters.fake_phone_verification import DeterministicFakePhoneVerificationAdapter
from xcia.config import RuntimeEnvironment, Xcia3RuntimeSettings
from xcia.domain.authentication import PhoneVerificationChallenge
from xcia.ports.authentication import PhoneVerificationProviderPort


@dataclass(frozen=True, slots=True)
class InfobipHttpResponse:
    status_code: int
    body: bytes


class InfobipHttpTransport(Protocol):
    def post(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> InfobipHttpResponse: ...


class UrllibInfobipHttpTransport:
    def post(
        self,
        *,
        url: str,
        headers: dict[str, str],
        body: bytes,
        timeout_seconds: int,
    ) -> InfobipHttpResponse:
        request = Request(url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
                return InfobipHttpResponse(response.status, response.read())
        except HTTPError as error:
            return InfobipHttpResponse(error.code, error.read())
        except (TimeoutError, URLError, OSError) as error:
            raise RuntimeError("Infobip transport unavailable") from error


@dataclass(frozen=True, slots=True)
class InfobipPhoneVerificationAdapter:
    """Server-side Infobip 2FA adapter; provider-specific details stay behind XCIA's port."""

    base_url: str
    application_id: str
    message_id: str
    sender_id: str
    api_key: str
    request_timeout_seconds: int
    challenge_ttl_seconds: int
    transport: InfobipHttpTransport

    def begin(self, phone: str, *, now: datetime) -> PhoneVerificationChallenge:
        response = self._post(
            path="/2fa/2/pin",
            payload={
                "applicationId": self.application_id,
                "messageId": self.message_id,
                "from": self.sender_id,
                "to": phone,
            },
        )
        if not 200 <= response.status_code < 300:
            raise ValueError("phone verification provider unavailable")
        payload = self._json_object(response.body)
        pin_id = payload.get("pinId")
        if not isinstance(pin_id, str) or not pin_id:
            raise ValueError("phone verification provider response is invalid")
        try:
            return PhoneVerificationChallenge(
                challenge_id=pin_id,
                expires_at=now + timedelta(seconds=self.challenge_ttl_seconds),
            )
        except ValueError as error:
            raise ValueError("phone verification provider response is invalid") from error

    def verify(self, challenge_id: str, proof: str, *, now: datetime) -> bool:
        del now
        try:
            response = self._post(
                path=f"/2fa/2/pin/{quote(challenge_id, safe='')}/verify",
                payload={"pin": proof},
            )
        except (RuntimeError, ValueError):
            return False
        if not 200 <= response.status_code < 300:
            return False
        try:
            payload = self._json_object(response.body)
        except ValueError:
            return False
        verified = payload.get("verified")
        return verified is True

    def _post(self, *, path: str, payload: dict[str, str]) -> InfobipHttpResponse:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return self.transport.post(
            url=f"{self.base_url.rstrip('/')}{path}",
            headers={
                "Authorization": f"App {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=body,
            timeout_seconds=self.request_timeout_seconds,
        )

    @staticmethod
    def _json_object(body: bytes) -> dict[str, object]:
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("provider response is not JSON") from error
        if not isinstance(decoded, dict):
            raise ValueError("provider response is not an object")
        return cast(dict[str, object], decoded)


def compose_phone_verification_provider(
    *,
    settings: Xcia3RuntimeSettings,
    environment: RuntimeEnvironment,
    fake_secret: bytes,
    transport: InfobipHttpTransport | None = None,
) -> PhoneVerificationProviderPort:
    if settings.phone_provider == "deterministic_fake":
        return DeterministicFakePhoneVerificationAdapter(
            environment=environment,
            secret=fake_secret,
            ttl_seconds=settings.challenge_ttl_seconds,
        )
    if settings.phone_provider != "infobip_2fa":
        raise ValueError("phone provider selection is invalid")
    base_url, application_id, message_id, sender_id = settings.require_infobip_configuration()
    api_key = os.environ.get(settings.infobip_api_key_env)
    if api_key is None or not api_key.strip():
        raise ValueError("Infobip API key binding is required")
    return InfobipPhoneVerificationAdapter(
        base_url=base_url,
        application_id=application_id,
        message_id=message_id,
        sender_id=sender_id,
        api_key=api_key,
        request_timeout_seconds=settings.infobip_request_timeout_seconds,
        challenge_ttl_seconds=settings.challenge_ttl_seconds,
        transport=transport if transport is not None else UrllibInfobipHttpTransport(),
    )
