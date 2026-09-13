from __future__ import annotations

from datetime import datetime
from typing import Protocol

from xcia.domain.authentication import PhoneVerificationChallenge


class PhoneVerificationProviderPort(Protocol):
    def begin(self, phone: str, *, now: datetime) -> PhoneVerificationChallenge: ...

    def verify(self, challenge_id: str, proof: str, *, now: datetime) -> bool: ...
