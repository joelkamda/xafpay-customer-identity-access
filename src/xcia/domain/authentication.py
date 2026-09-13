from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from xcia.domain.models import FrozenModel


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    LOCKED = "locked"


class AuthenticationFailure(FrozenModel):
    code: str = "authentication_failed"


class PhoneVerificationChallenge(FrozenModel):
    challenge_id: str = Field(min_length=16, max_length=255)
    expires_at: datetime
