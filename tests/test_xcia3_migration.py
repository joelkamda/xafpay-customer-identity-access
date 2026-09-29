from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from xcia.persistence import XciaDatabase


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_XCIA3_REVISION = "xcia3_0001"
CURRENT_REVISION = "xcia_phone_challenge_bind_0001"


@pytest.fixture()
def xcia3_database(xcia2_database_url: str) -> Iterator[XciaDatabase]:
    previous_database_url = os.environ.get("XCIA2_DATABASE_URL")
    os.environ["XCIA2_DATABASE_URL"] = xcia2_database_url
    config = Config(str(ROOT / "alembic.ini"))
    downgraded = False
    database: XciaDatabase | None = None
    try:
        command.downgrade(config, HISTORICAL_XCIA3_REVISION)
        downgraded = True
        database = XciaDatabase(xcia2_database_url)
        yield database
    finally:
        if database is not None:
            database.dispose()
        if downgraded:
            command.upgrade(config, CURRENT_REVISION)
        if previous_database_url is None:
            os.environ.pop("XCIA2_DATABASE_URL", None)
        else:
            os.environ["XCIA2_DATABASE_URL"] = previous_database_url


def test_xcia3_durable_tables_are_present(xcia3_database: XciaDatabase) -> None:
    assert xcia3_database.schema_revision() == HISTORICAL_XCIA3_REVISION
    tables = inspect(xcia3_database.engine).get_table_names()
    assert "xcia_customer_pin_credentials" in tables
    assert "xcia_authentication_buckets" in tables
    assert "xcia_trusted_devices" in tables
