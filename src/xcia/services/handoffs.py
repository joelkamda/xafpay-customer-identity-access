from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime

from xcia.adapters.postgres import (
    DurableWalletSessionHandoffStore,
    WalletSessionHandoffContext,
    WalletSessionHandoffMaterial,
)
from xcia.config import XciaSettings
from xcia.domain import DurableSessionSnapshot


class HandoffDeniedError(ValueError):
    """Trusted handoff was denied without disclosing which trust check failed."""


class HandoffServiceAuthenticationError(HandoffDeniedError):
    """Wallet Web service authentication failed."""


class HandoffUnavailableError(RuntimeError):
    """Trusted handoff persistence or runtime dependency is unavailable."""


@dataclass(frozen=True, slots=True)
class TrustedWalletSessionContext:
    auth_completion_id: str
    xcia_session_cookie_name: str
    xcia_session_cookie_value: str
    auth_time: datetime
    sender_jkt: str
    security_version: int
    authoritative_xcia_idle_expires_at: datetime
    authoritative_xcia_absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class WalletSessionHandoffService:
    settings: XciaSettings
    store: DurableWalletSessionHandoffStore
    service_token: str
    relying_party: str = "WALLET"

    def __post_init__(self) -> None:
        if len(self.service_token.encode("utf-8")) < 32:
            raise ValueError("Wallet Web handoff service token must contain at least 256 bits.")

    @classmethod
    def from_settings(
        cls,
        settings: XciaSettings,
        store: DurableWalletSessionHandoffStore,
    ) -> WalletSessionHandoffService:
        token = settings.wallet_web_handoff_service_token
        if token is None:
            raise ValueError("XCIA Wallet Web handoff service token is not configured.")
        return cls(settings=settings, store=store, service_token=token)

    def issue(
        self,
        *,
        session: DurableSessionSnapshot,
        trusted_origin: str,
        now: datetime | None = None,
    ) -> WalletSessionHandoffMaterial:
        self._require_trusted_origin(trusted_origin)
        try:
            return self.store.issue(
                session_sid=session.sid,
                relying_party=self.relying_party,
                sender_jkt=session.sender_jkt,
                security_version=session.security_version,
                trusted_origin=trusted_origin,
                now=now,
            )
        except ValueError as exc:
            raise HandoffDeniedError("trusted handoff issuance denied") from exc
        except Exception as exc:
            raise HandoffUnavailableError("trusted handoff store unavailable") from exc

    def redeem(
        self,
        *,
        handoff_code: str,
        sender_jkt: str,
        trusted_origin: str,
        presented_service_token: str,
        now: datetime | None = None,
    ) -> TrustedWalletSessionContext:
        self._require_service_token(presented_service_token)
        self._require_trusted_origin(trusted_origin)
        try:
            context = self.store.redeem(
                handoff_code=handoff_code,
                relying_party=self.relying_party,
                sender_jkt=sender_jkt,
                trusted_origin=trusted_origin,
                now=now,
            )
        except ValueError as exc:
            raise HandoffDeniedError("trusted handoff redemption denied") from exc
        except Exception as exc:
            raise HandoffUnavailableError("trusted handoff store unavailable") from exc
        return self._trusted_context(context)

    def reconcile(
        self,
        *,
        auth_completion_id: str,
        sender_jkt: str,
        trusted_origin: str,
        presented_service_token: str,
        now: datetime | None = None,
    ) -> TrustedWalletSessionContext:
        self._require_service_token(presented_service_token)
        self._require_trusted_origin(trusted_origin)
        try:
            context = self.store.reconcile(
                auth_completion_id=auth_completion_id,
                relying_party=self.relying_party,
                sender_jkt=sender_jkt,
                trusted_origin=trusted_origin,
                now=now,
            )
        except ValueError as exc:
            raise HandoffDeniedError("trusted handoff reconciliation denied") from exc
        except Exception as exc:
            raise HandoffUnavailableError("trusted handoff store unavailable") from exc
        return self._trusted_context(context)

    def _trusted_context(
        self,
        context: WalletSessionHandoffContext,
    ) -> TrustedWalletSessionContext:
        return TrustedWalletSessionContext(
            auth_completion_id=context.auth_completion_id,
            xcia_session_cookie_name=self.settings.session_cookie_name,
            xcia_session_cookie_value=context.session_sid,
            auth_time=context.auth_time,
            sender_jkt=context.sender_jkt,
            security_version=context.security_version,
            authoritative_xcia_idle_expires_at=context.idle_expires_at,
            authoritative_xcia_absolute_expires_at=context.absolute_expires_at,
        )

    def _require_service_token(self, presented: str) -> None:
        if not presented or not secrets.compare_digest(
            self.service_token.encode("utf-8"),
            presented.encode("utf-8"),
        ):
            raise HandoffServiceAuthenticationError("Wallet Web service authentication denied.")

    def _require_trusted_origin(self, origin: str) -> None:
        if origin not in self.settings.trusted_origins:
            raise HandoffDeniedError("trusted Wallet Web origin required")
