from __future__ import annotations

from pathlib import Path

from xcia.persistence import XciaDatabase
from xcia.persistence.schema import Base


def test_database_schema_is_xcia_owned_only() -> None:
    table_names = set(Base.metadata.tables)
    assert table_names
    assert all(name.startswith("xcia_") for name in table_names)


def test_expected_migration_is_current(database: XciaDatabase) -> None:
    assert database.schema_revision() == "xcia3_0001"


def test_no_public_login_routes_are_implemented() -> None:
    source = Path("src/xcia/app.py").read_text(encoding="utf-8").lower()
    forbidden = ("\"/login\"", "/oauth", "/oidc", "/callback", "/password", "/otp")
    assert all(route not in source for route in forbidden)
