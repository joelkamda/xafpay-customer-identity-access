from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine

from xcia.persistence.schema import Base

database_url = os.environ.get("XCIA2_DATABASE_URL")
if database_url is None or not database_url.startswith("postgresql+psycopg://"):
    raise RuntimeError("XCIA2_DATABASE_URL must be an explicit PostgreSQL psycopg URL")

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    raise RuntimeError("XCIA2 migrations require an online disposable PostgreSQL target")


def run_migrations_online() -> None:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
