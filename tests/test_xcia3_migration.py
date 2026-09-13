from __future__ import annotations

from sqlalchemy import inspect

from xcia.persistence import XciaDatabase


def test_xcia3_durable_tables_are_present(database: XciaDatabase) -> None:
    assert database.schema_revision() == "xcia3_0001"
    tables = inspect(database.engine).get_table_names()
    assert "xcia_customer_pin_credentials" in tables
    assert "xcia_authentication_buckets" in tables
    assert "xcia_trusted_devices" in tables
