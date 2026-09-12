from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ConfirmationClaim(FrozenModel):
    jkt: str = Field(min_length=16, max_length=256)


class CustomerAuthAssertionClaims(FrozenModel):
    iss: str = Field(min_length=1)
    sub: str = Field(min_length=16, max_length=255)
    aud: str = Field(min_length=1)
    iat: int = Field(ge=0)
    nbf: int = Field(ge=0)
    exp: int = Field(gt=0)
    jti: str = Field(min_length=16, max_length=255)
    sid: str = Field(min_length=16, max_length=255)
    auth_time: int = Field(ge=0)
    cnf: ConfirmationClaim

    @model_validator(mode="after")
    def validate_times(self) -> CustomerAuthAssertionClaims:
        if self.nbf > self.exp:
            raise ValueError("nbf must not be after exp")
        if self.iat > self.exp:
            raise ValueError("iat must not be after exp")
        if self.auth_time > self.iat:
            raise ValueError("auth_time must not be after iat")
        return self


class ExternalCustomerSubject(FrozenModel):
    value: str = Field(min_length=16, max_length=255)
    relying_party: str = Field(min_length=1, max_length=255)
    environment: str = Field(min_length=1, max_length=64)


class RelyingPartyTrustPolicy(FrozenModel):
    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    allowed_algorithm: str = "ES256"
    assertion_lifetime_seconds: int = 300
    clock_skew_seconds: int = 60
    sender_constraint_required: bool = True

    @model_validator(mode="after")
    def validate_v1_defaults(self) -> RelyingPartyTrustPolicy:
        if self.allowed_algorithm != "ES256":
            raise ValueError("XCIA1 requires ES256")
        if self.assertion_lifetime_seconds != 300:
            raise ValueError("XCIA1 assertion lifetime is 300 seconds")
        if self.clock_skew_seconds != 60:
            raise ValueError("XCIA1 clock skew is 60 seconds")
        if not self.sender_constraint_required:
            raise ValueError("XCIA1 relying-party policy requires sender constraint")
        return self


class SessionReference(FrozenModel):
    sid: str = Field(min_length=16, max_length=255)


class RefreshFamilyReference(FrozenModel):
    family_id: str = Field(min_length=16, max_length=255)
    generation: int = Field(ge=0)


class SigningKeyState(StrEnum):
    ACTIVE_SIGNING = "active_signing"
    VERIFY_ONLY_OVERLAP = "verify_only_overlap"
    RETIRED = "retired"
    REVOKED = "revoked"


class SigningKeyReference(FrozenModel):
    kid: str = Field(min_length=8, max_length=255)
    algorithm: str = "ES256"
    state: SigningKeyState


class RevocationDecision(StrEnum):
    ALLOW = "allow"
    DENY_REVOKED = "deny_revoked"


class ReplayDecision(StrEnum):
    ALLOW = "allow"
    DENY_REPLAY = "deny_replay"
