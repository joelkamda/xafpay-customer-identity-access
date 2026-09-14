from __future__ import annotations

from pathlib import Path


def test_adapter_has_no_live_provider_calls_or_secret_value() -> None:
    source = (
        Path(__file__).parents[1]
        / "src"
        / "xcia"
        / "adapters"
        / "infobip_phone_verification.py"
    ).read_text(encoding="utf-8")
    assert "test-not-a-real-infobip-key" not in source
    assert "https://api.infobip.com" not in source
    assert "wallet" not in source.lower()
    assert "xcia assertion" not in source.lower()


def test_documentation_does_not_overstate_live_provider_validation() -> None:
    content = (
        Path(__file__).parents[1]
        / "docs"
        / "runtime"
        / "XCIA4_REAL_PHONE_VERIFICATION_PROVIDER.md"
    ).read_text(encoding="utf-8")
    assert "No SMS was sent" in content
    assert "production readiness" not in content.lower()
