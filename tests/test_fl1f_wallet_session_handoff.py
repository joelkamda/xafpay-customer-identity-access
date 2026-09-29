from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from xcia.adapters import WalletSessionHandoffContext, WalletSessionHandoffMaterial
from xcia.config import RuntimeEnvironment, XciaSettings
from xcia.services import (
    HandoffDeniedError,
    HandoffServiceAuthenticationError,
    WalletSessionHandoffService,
)

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "src/xcia/app.py").read_text(encoding="utf-8")
STORE = (ROOT / "src/xcia/adapters/postgres.py").read_text(encoding="utf-8")
MIGRATION = (
    ROOT / "migrations/versions/fl1f_0001_wallet_session_handoffs.py"
).read_text(encoding="utf-8")


class FakeStore:
    def __init__(self) -> None:
        now = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
        self.material = WalletSessionHandoffMaterial(
            auth_completion_id="ac_0123456789abcdefghijkl",
            handoff_code="A" * 43,
            handoff_expires_at=now + timedelta(seconds=60),
        )
        self.context = WalletSessionHandoffContext(
            auth_completion_id=self.material.auth_completion_id,
            session_sid="sid_fl1f_server_secret_00000000000001",
            auth_time=now,
            sender_jkt="sender_jkt_fl1f_0123456789abcdef",
            security_version=7,
            idle_expires_at=now + timedelta(minutes=10),
            absolute_expires_at=now + timedelta(hours=6),
        )

    def issue(self, **_: object) -> WalletSessionHandoffMaterial:
        return self.material

    def redeem(self, **_: object) -> WalletSessionHandoffContext:
        return self.context

    def reconcile(self, **_: object) -> WalletSessionHandoffContext:
        return self.context


def settings() -> XciaSettings:
    return XciaSettings(
        environment=RuntimeEnvironment.TEST,
        issuer="urn:xafpay:customer-auth:test",
        audience="urn:xafpay:wallet-api:test",
        trusted_origins=("https://wallet.test",),
        wallet_web_handoff_service_token="T" * 32,
    )


def service() -> WalletSessionHandoffService:
    return WalletSessionHandoffService(
        settings=settings(),
        store=FakeStore(),  # type: ignore[arg-type]
        service_token="T" * 32,
    )


def test_x01_successful_login_issues_one_bound_handoff() -> None:
    assert '@app.post("/bff/auth/login"' in APP
    assert "return authentication_response(request, result.session)" in APP


def test_x02_successful_enrollment_issues_one_bound_handoff() -> None:
    assert '"/bff/auth/enrollment/complete"' in APP
    assert "return authentication_response(request, result.authentication.session)" in APP


def test_x03_successful_recovery_issues_one_bound_handoff() -> None:
    assert '@app.post("/bff/auth/recovery/complete"' in APP
    assert "handoff_code" in APP and "handoff_expires_at" in APP


def test_x04_successful_step_up_issues_one_bound_handoff() -> None:
    assert '@app.post("/bff/auth/device/step-up"' in APP
    assert "return pin_login(request, response, body)" in APP


def test_x05_handoff_code_is_256_bit_opaque_and_digest_only() -> None:
    assert "secrets.token_urlsafe(32)" in STORE
    assert 'hashlib.sha256(handoff_code.encode("utf-8")).digest()' in STORE
    assert 'sa.Column("handoff_code"' not in MIGRATION
    assert 'sa.Column("code_digest", sa.LargeBinary(), nullable=False)' in MIGRATION


def test_x06_redeem_returns_exact_xcia_cookie_name_and_value() -> None:
    result = service().redeem(
        handoff_code="A" * 43,
        sender_jkt="sender_jkt_fl1f_0123456789abcdef",
        trusted_origin="https://wallet.test",
        presented_service_token="T" * 32,
    )
    assert result.xcia_session_cookie_name == "__Host-xcia_session"
    assert result.xcia_session_cookie_value == "sid_fl1f_server_secret_00000000000001"


def test_x07_redeem_propagates_exact_idle_expiry() -> None:
    result = service().redeem(
        handoff_code="A" * 43,
        sender_jkt="sender_jkt_fl1f_0123456789abcdef",
        trusted_origin="https://wallet.test",
        presented_service_token="T" * 32,
    )
    assert result.authoritative_xcia_idle_expires_at == service().store.context.idle_expires_at  # type: ignore[attr-defined]


def test_x08_redeem_propagates_absolute_auth_time_and_security_version() -> None:
    svc = service()
    result = svc.redeem(
        handoff_code="A" * 43,
        sender_jkt="sender_jkt_fl1f_0123456789abcdef",
        trusted_origin="https://wallet.test",
        presented_service_token="T" * 32,
    )
    assert result.authoritative_xcia_absolute_expires_at == svc.store.context.absolute_expires_at  # type: ignore[attr-defined]
    assert result.auth_time == svc.store.context.auth_time  # type: ignore[attr-defined]
    assert result.security_version == 7


def test_x09_one_time_code_replay_fails_closed() -> None:
    assert "if row.redeemed_at is not None:" in STORE
    assert 'raise ValueError("handoff is already redeemed")' in STORE


def test_x10_expired_handoff_fails_closed() -> None:
    assert "if moment >= row.expires_at:" in STORE
    assert 'raise ValueError("handoff is expired")' in STORE


def test_x11_wrong_rp_or_service_principal_fails_closed() -> None:
    assert "if row.relying_party != relying_party:" in STORE
    with pytest.raises(HandoffServiceAuthenticationError):
        service().redeem(
            handoff_code="A" * 43,
            sender_jkt="sender_jkt_fl1f_0123456789abcdef",
            trusted_origin="https://wallet.test",
            presented_service_token="wrong" * 8,
        )


def test_x12_wrong_trusted_origin_fails_closed() -> None:
    with pytest.raises(HandoffDeniedError):
        service().redeem(
            handoff_code="A" * 43,
            sender_jkt="sender_jkt_fl1f_0123456789abcdef",
            trusted_origin="https://attacker.test",
            presented_service_token="T" * 32,
        )


def test_x13_sender_jkt_mismatch_fails_closed() -> None:
    assert "row.sender_jkt != sender_jkt or session_row.sender_jkt != sender_jkt" in STORE


def test_x14_revoked_xcia_session_cannot_be_redeemed() -> None:
    assert "if not snapshot.is_active(moment):" in STORE
    assert "revoked_at" in STORE


def test_x15_expired_xcia_session_cannot_be_redeemed() -> None:
    assert "snapshot.is_active(moment)" in STORE
    assert "idle_expires_at" in STORE and "absolute_expires_at" in STORE


def test_x16_lost_response_before_effect_can_retry_unconsumed_code() -> None:
    assert "row.redeemed_at = moment" in STORE
    assert "with session.begin():" in STORE


def test_x17_lost_response_after_effect_reconciles_by_completion_id() -> None:
    assert "def reconcile(" in STORE
    assert "WalletSessionHandoffRow.auth_completion_id == auth_completion_id" in STORE


def test_x18_reconciliation_window_expiry_fails_closed() -> None:
    assert "moment >= row.reconcile_expires_at" in STORE
    assert "RECONCILIATION_WINDOW_SECONDS = 120" in STORE


def test_x19_xcia_logout_revokes_session_and_clears_cookie() -> None:
    assert '@app.post("/bff/auth/logout"' in APP
    assert "service.sessions.revoke_session(sid)" in APP
    assert "response.delete_cookie(" in APP


def test_x20_missing_or_invalid_service_token_fails_closed() -> None:
    assert "secrets.compare_digest(" in (
        ROOT / "src/xcia/services/handoffs.py"
    ).read_text(encoding="utf-8")
    with pytest.raises(HandoffServiceAuthenticationError):
        service().reconcile(
            auth_completion_id="ac_0123456789abcdefghijkl",
            sender_jkt="sender_jkt_fl1f_0123456789abcdef",
            trusted_origin="https://wallet.test",
            presented_service_token="",
        )
