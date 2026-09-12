from __future__ import annotations

from typing import Protocol

from xcia.domain import RefreshFamilyReference, SessionReference


class SessionAuthority(Protocol):
    def create_session(self) -> SessionReference: ...

    def rotate_session_identifier(self, session: SessionReference) -> SessionReference: ...

    def invalidate_session(self, session: SessionReference) -> None: ...

    def is_sid_revoked(self, sid: str) -> bool: ...

    def issue_refresh_family(self, session: SessionReference) -> RefreshFamilyReference: ...

    def rotate_refresh_family(
        self,
        family: RefreshFamilyReference,
    ) -> RefreshFamilyReference: ...

    def detect_refresh_reuse(self, family: RefreshFamilyReference) -> bool: ...
