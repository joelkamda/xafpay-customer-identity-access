from __future__ import annotations

from dataclasses import dataclass

from xcia.config import XciaSettings


@dataclass(frozen=True, slots=True)
class WalletRelyingPartyProfile:
    relying_party: str
    issuer: str
    audience: str
    environment: str
    assertion_lifetime_seconds: int
    sender_constraint_required: bool

    @classmethod
    def from_settings(cls, settings: XciaSettings) -> WalletRelyingPartyProfile:
        expected_audience = f"urn:xafpay:wallet-api:{settings.environment.value}"
        if settings.audience != expected_audience:
            raise ValueError("Wallet relying-party audience must match the runtime environment")
        if settings.assertion_lifetime_seconds != 300:
            raise ValueError("Wallet relying-party assertion lifetime must remain 300 seconds")

        return cls(
            relying_party="WALLET_API",
            issuer=settings.issuer,
            audience=expected_audience,
            environment=settings.environment.value,
            assertion_lifetime_seconds=300,
            sender_constraint_required=True,
        )
