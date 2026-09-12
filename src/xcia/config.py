from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class XciaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XCIA_", extra="forbid", frozen=True)

    environment: RuntimeEnvironment
    issuer: str = Field(min_length=1)
    audience: str = Field(min_length=1)
    trusted_origins: tuple[str, ...] = Field(min_length=1)
    session_cookie_name: str = "__Host-xcia_session"
    session_cookie_samesite: str = "lax"
    assertion_lifetime_seconds: int = 300
    clock_skew_seconds: int = 60

    @field_validator("trusted_origins")
    @classmethod
    def validate_origins(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for origin in value:
            parts = urlsplit(origin)
            if parts.scheme not in {"https", "http"} or not parts.netloc:
                raise ValueError("trusted origins must be absolute http(s) origins")
            if parts.path not in {"", "/"} or parts.query or parts.fragment:
                raise ValueError("trusted origins must not contain path, query, or fragment")
            normalized.append(f"{parts.scheme}://{parts.netloc}")
        if len(set(normalized)) != len(normalized):
            raise ValueError("trusted origins must be unique")
        return tuple(normalized)

    @model_validator(mode="after")
    def validate_trust_configuration(self) -> XciaSettings:
        expected_issuer = f"urn:xafpay:customer-auth:{self.environment.value}"
        if self.issuer != expected_issuer:
            raise ValueError(f"issuer must equal {expected_issuer}")

        expected_audience = f"urn:xafpay:wallet-api:{self.environment.value}"
        if self.audience != expected_audience:
            raise ValueError(f"audience must equal {expected_audience}")

        if not self.session_cookie_name.startswith("__Host-"):
            raise ValueError("session cookie must be __Host- compatible")
        if self.session_cookie_samesite.lower() != "lax":
            raise ValueError("XCIA1 SameSite baseline is Lax")
        if self.assertion_lifetime_seconds != 300:
            raise ValueError("XCIA1 assertion lifetime default is 300 seconds")
        if self.clock_skew_seconds != 60:
            raise ValueError("XCIA1 clock skew default is 60 seconds")
        return self

    @classmethod
    def from_environment(cls) -> XciaSettings:
        # BaseSettings resolves required values from XCIA_* environment variables.
        return cls()  # pyright: ignore[reportCallIssue]
