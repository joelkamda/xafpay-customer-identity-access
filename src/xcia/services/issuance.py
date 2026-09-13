from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from xcia.adapters import DurableSessionStore
from xcia.config import XciaSettings
from xcia.domain import ConfirmationClaim, CustomerAuthAssertionClaims
from xcia.ports import AssertionSigner


class UntrustedSessionError(ValueError):
    pass


class SenderConstraintError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DurableAssertionIssuer:
    settings: XciaSettings
    sessions: DurableSessionStore
    signer: AssertionSigner

    def issue(
        self,
        *,
        sid: str,
        sender_jkt: str,
        now: datetime | None = None,
    ) -> str:
        moment = now if now is not None else datetime.now(UTC)
        if moment.tzinfo is None:
            raise ValueError("issuance time must be timezone aware")

        try:
            session = self.sessions.require_active_session(sid, at=moment)
        except ValueError as exc:
            raise UntrustedSessionError("trusted authenticated session is required") from exc

        if not sender_jkt or session.sender_jkt != sender_jkt:
            raise SenderConstraintError("sender proof must match the authenticated session")

        claims = CustomerAuthAssertionClaims(
            iss=self.settings.issuer,
            sub=session.sub,
            aud=self.settings.audience,
            iat=int(moment.timestamp()),
            nbf=int(moment.timestamp()),
            exp=int(moment.timestamp()) + self.settings.assertion_lifetime_seconds,
            jti=f"jti_{uuid.uuid4().hex}",
            sid=session.sid,
            auth_time=int(session.auth_time.timestamp()),
            cnf=ConfirmationClaim(jkt=sender_jkt),
        )
        return self.signer.sign(claims)
