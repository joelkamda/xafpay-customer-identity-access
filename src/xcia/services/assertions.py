from __future__ import annotations

from dataclasses import dataclass

from xcia.domain import (
    CustomerAuthAssertionClaims,
    RelyingPartyTrustPolicy,
    ReplayDecision,
    RevocationDecision,
)
from xcia.ports.crypto import AssertionVerifier
from xcia.ports.revocation import ReplayDefense, RevocationAuthority


class SenderBindingError(ValueError):
    pass


class RevokedSessionError(ValueError):
    pass


class ReplayRejectedError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AssertionTrustService:
    verifier: AssertionVerifier
    revocation: RevocationAuthority
    replay: ReplayDefense

    def validate(
        self,
        *,
        token: str,
        policy: RelyingPartyTrustPolicy,
        sender_jkt: str,
    ) -> CustomerAuthAssertionClaims:
        claims = self.verifier.verify(token, policy)

        if policy.sender_constraint_required and claims.cnf.jkt != sender_jkt:
            raise SenderBindingError("DPoP proof key does not match cnf.jkt")

        if self.revocation.session_decision(claims.sid) is not RevocationDecision.ALLOW:
            raise RevokedSessionError("sid is revoked")

        if self.replay.evaluate_jti(claims.jti) is not ReplayDecision.ALLOW:
            raise ReplayRejectedError("jti replay rejected")

        return claims
