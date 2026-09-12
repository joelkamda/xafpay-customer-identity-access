from __future__ import annotations

from xcia.domain import (
    RefreshFamilyReference,
    ReplayDecision,
    RevocationDecision,
    SessionReference,
)


class FakeSessionAuthority:
    def __init__(self) -> None:
        self._session_counter = 0
        self._family_counter = 0
        self._revoked_sids: set[str] = set()
        self._latest_generation: dict[str, int] = {}

    def create_session(self) -> SessionReference:
        self._session_counter += 1
        return SessionReference(sid=f"sid_fake_{self._session_counter:016d}")

    def rotate_session_identifier(self, session: SessionReference) -> SessionReference:
        self.invalidate_session(session)
        return self.create_session()

    def invalidate_session(self, session: SessionReference) -> None:
        self._revoked_sids.add(session.sid)

    def is_sid_revoked(self, sid: str) -> bool:
        return sid in self._revoked_sids

    def issue_refresh_family(self, session: SessionReference) -> RefreshFamilyReference:
        if self.is_sid_revoked(session.sid):
            raise ValueError("cannot issue refresh family for revoked session")
        self._family_counter += 1
        family_id = f"rf_fake_{self._family_counter:016d}"
        self._latest_generation[family_id] = 0
        return RefreshFamilyReference(family_id=family_id, generation=0)

    def rotate_refresh_family(
        self,
        family: RefreshFamilyReference,
    ) -> RefreshFamilyReference:
        current = self._latest_generation.get(family.family_id)
        if current is None or current != family.generation:
            raise ValueError("refresh reuse detected")
        next_generation = current + 1
        self._latest_generation[family.family_id] = next_generation
        return RefreshFamilyReference(
            family_id=family.family_id,
            generation=next_generation,
        )

    def detect_refresh_reuse(self, family: RefreshFamilyReference) -> bool:
        current = self._latest_generation.get(family.family_id)
        return current is None or current != family.generation


class FakeRevocationAuthority:
    def __init__(self) -> None:
        self.revoked_sids: set[str] = set()
        self.revoked_families: set[str] = set()
        self.revoked_kids: set[str] = set()

    def session_decision(self, sid: str) -> RevocationDecision:
        if sid in self.revoked_sids:
            return RevocationDecision.DENY_REVOKED
        return RevocationDecision.ALLOW

    def refresh_family_decision(self, family_id: str) -> RevocationDecision:
        if family_id in self.revoked_families:
            return RevocationDecision.DENY_REVOKED
        return RevocationDecision.ALLOW

    def signing_key_decision(self, kid: str) -> RevocationDecision:
        if kid in self.revoked_kids:
            return RevocationDecision.DENY_REVOKED
        return RevocationDecision.ALLOW


class FakeReplayDefense:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def evaluate_jti(self, jti: str) -> ReplayDecision:
        if jti in self.seen:
            return ReplayDecision.DENY_REPLAY
        self.seen.add(jti)
        return ReplayDecision.ALLOW
