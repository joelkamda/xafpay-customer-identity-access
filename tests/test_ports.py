from __future__ import annotations

import pytest

from tests.support.fakes import FakeReplayDefense, FakeRevocationAuthority, FakeSessionAuthority
from xcia.domain import ReplayDecision, RevocationDecision


def test_session_rotation_invalidates_previous_sid() -> None:
    authority = FakeSessionAuthority()
    original = authority.create_session()
    rotated = authority.rotate_session_identifier(original)
    assert authority.is_sid_revoked(original.sid) is True
    assert authority.is_sid_revoked(rotated.sid) is False
    assert rotated.sid != original.sid


def test_refresh_family_rotates_on_use() -> None:
    authority = FakeSessionAuthority()
    session = authority.create_session()
    first = authority.issue_refresh_family(session)
    second = authority.rotate_refresh_family(first)
    assert second.family_id == first.family_id
    assert second.generation == first.generation + 1


def test_refresh_family_reuse_is_detected() -> None:
    authority = FakeSessionAuthority()
    session = authority.create_session()
    first = authority.issue_refresh_family(session)
    authority.rotate_refresh_family(first)
    assert authority.detect_refresh_reuse(first) is True
    with pytest.raises(ValueError):
        authority.rotate_refresh_family(first)


def test_sid_revocation_decision_behavior() -> None:
    authority = FakeRevocationAuthority()
    sid = "sid_01JTESTSESSION000000001"
    assert authority.session_decision(sid) is RevocationDecision.ALLOW
    authority.revoked_sids.add(sid)
    assert authority.session_decision(sid) is RevocationDecision.DENY_REVOKED


def test_jti_replay_decision_behavior() -> None:
    replay = FakeReplayDefense()
    jti = "jti_01JTESTASSERTION00000001"
    assert replay.evaluate_jti(jti) is ReplayDecision.ALLOW
    assert replay.evaluate_jti(jti) is ReplayDecision.DENY_REPLAY
