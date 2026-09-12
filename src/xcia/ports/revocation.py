from __future__ import annotations

from typing import Protocol

from xcia.domain import ReplayDecision, RevocationDecision


class RevocationAuthority(Protocol):
    def session_decision(self, sid: str) -> RevocationDecision: ...

    def refresh_family_decision(self, family_id: str) -> RevocationDecision: ...

    def signing_key_decision(self, kid: str) -> RevocationDecision: ...


class ReplayDefense(Protocol):
    def evaluate_jti(self, jti: str) -> ReplayDecision: ...
