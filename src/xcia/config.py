from __future__ import annotations

import re
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
        return cls()  # pyright: ignore[reportCallIssue]


class Xcia2RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XCIA2_", extra="forbid", frozen=True)

    database_url: str = Field(min_length=1)
    signing_key_kid: str = Field(min_length=8, max_length=255)
    signing_private_key_env: str = Field(min_length=1, max_length=255)
    migration_revision: str = "xcia2_0001"

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        if not value.startswith("postgresql+psycopg://"):
            raise ValueError("XCIA2 requires PostgreSQL through the psycopg driver")
        lowered = value.lower()
        forbidden = ("wallet", "xbos", "customer-channel", "customer_channel", "core-ledger")
        if any(marker in lowered for marker in forbidden):
            raise ValueError("XCIA2 database URL appears to target another project database")
        return value

    @field_validator("signing_private_key_env")
    @classmethod
    def validate_secret_env_name(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,254}", value) is None:
            raise ValueError(
                "signing_private_key_env must be an uppercase environment variable name"
            )
        return value


class Xcia3RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="XCIA3_", extra="forbid", frozen=True)

    credential_secret_env: str = Field(min_length=1, max_length=255)
    phone_provider: str = "deterministic_fake"
    challenge_ttl_seconds: int = Field(default=300, ge=30, le=900)
    challenge_attempt_limit: int = Field(default=5, ge=1, le=10)
    lockout_after_failures: int = Field(default=5, ge=3, le=20)
    lockout_seconds: int = Field(default=900, ge=60, le=86400)
    trusted_device_ttl_seconds: int = Field(default=2592000, ge=3600, le=31536000)
    scrypt_n: int = 32768
    scrypt_r: int = 8
    scrypt_p: int = 1

    @field_validator("credential_secret_env")
    @classmethod
    def validate_credential_secret_env(cls, value: str) -> str:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,254}", value) is None:
            raise ValueError("credential_secret_env must name an uppercase environment variable")
        return value

    @model_validator(mode="after")
    def validate_security_policy(self) -> Xcia3RuntimeSettings:
        if self.phone_provider != "deterministic_fake":
            raise ValueError("XCIA3 authorizes only the deterministic fake phone provider")
        if (self.scrypt_n, self.scrypt_r, self.scrypt_p) != (32768, 8, 1):
            raise ValueError("XCIA3 Scrypt policy must remain fixed")
        return self

    def validate_for_environment(
        self,
        environment: RuntimeEnvironment,
        available_secret: bytes | None,
    ) -> None:
        if available_secret is None or len(available_secret) < 32:
            raise ValueError("XCIA3 credential secret is required")
        if environment is RuntimeEnvironment.PRODUCTION:
            raise ValueError("XCIA3 fake phone provider is forbidden in production")
