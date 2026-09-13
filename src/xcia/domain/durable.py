from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field, model_validator

from xcia.domain.models import ExternalCustomerSubject, FrozenModel, SigningKeyState


class TrustedAuthenticationContext(FrozenModel):
    subject: ExternalCustomerSubject
    auth_time: datetime
    sender_jkt: str = Field(min_length=16, max_length=256)
    trust_source: str = Field(min_length=3, max_length=128)

    @model_validator(mode="after")
    def require_aware_auth_time(self) -> TrustedAuthenticationContext:
        if self.auth_time.tzinfo is None:
            raise ValueError("auth_time must be timezone aware")
        return self


class DurableSessionSnapshot(FrozenModel):
    sid: str = Field(min_length=16, max_length=255)
    sub: str = Field(min_length=16, max_length=255)
    sender_jkt: str = Field(min_length=16, max_length=256)
    created_at: datetime
    auth_time: datetime
    last_activity: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None = None
    refresh_family_id: str | None = None
    security_version: int = Field(default=1, ge=1)

    def is_active(self, at: datetime | None = None) -> bool:
        moment = at if at is not None else datetime.now(UTC)
        if moment.tzinfo is None:
            raise ValueError("activity check time must be timezone aware")
        return (
            self.revoked_at is None
            and moment >= self.created_at
            and moment >= self.auth_time
            and moment < self.idle_expires_at
            and moment < self.absolute_expires_at
        )


class RefreshTokenMaterial(FrozenModel):
    family_id: str = Field(min_length=16, max_length=255)
    generation: int = Field(ge=0)
    secret: str = Field(min_length=32, max_length=512)
    expires_at: datetime


class SigningKeyMetadata(FrozenModel):
    kid: str = Field(min_length=8, max_length=255)
    issuer: str = Field(min_length=1)
    environment: str = Field(min_length=1, max_length=64)
    algorithm: str = "ES256"
    state: SigningKeyState
    public_jwk: dict[str, Any]
    not_before: datetime
    not_after: datetime | None = None
