from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta

from xcia.config import RuntimeEnvironment
from xcia.domain.authentication import PhoneVerificationChallenge


class DeterministicFakePhoneVerificationAdapter:
    """Test/staging-only proof provider; it never sends telephone traffic."""

    def __init__(
        self,
        *,
        environment: RuntimeEnvironment,
        secret: bytes,
        ttl_seconds: int = 300,
    ) -> None:
        if environment is RuntimeEnvironment.PRODUCTION:
            raise ValueError("fake phone verification is forbidden in production")
        if len(secret) < 32:
            raise ValueError("fake phone verification secret is too short")
        self._secret = secret
        self._ttl_seconds = ttl_seconds
        self._challenges: dict[str, tuple[str, datetime, bool]] = {}

    def begin(self, phone: str, *, now: datetime) -> PhoneVerificationChallenge:
        challenge_id = f"fake_phone_{uuid.uuid4().hex}"
        expires_at = now + timedelta(seconds=self._ttl_seconds)
        phone_digest = hmac.new(self._secret, phone.encode("utf-8"), hashlib.sha256).hexdigest()
        self._challenges[challenge_id] = (phone_digest, expires_at, False)
        return PhoneVerificationChallenge(challenge_id=challenge_id, expires_at=expires_at)

    def expected_proof(self, challenge_id: str) -> str:
        row = self._challenges.get(challenge_id)
        if row is None:
            return ""
        message = f"fake-proof:{challenge_id}:{row[0]}".encode("ascii")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()[:12]

    def verify(self, challenge_id: str, proof: str, *, now: datetime) -> bool:
        row = self._challenges.get(challenge_id)
        if row is None or row[2] or now >= row[1]:
            return False
        expected = self.expected_proof(challenge_id)
        if not hmac.compare_digest(expected, proof):
            return False
        self._challenges[challenge_id] = (row[0], row[1], True)
        return True
