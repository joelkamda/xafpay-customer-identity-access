from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker


class XciaDatabase:
    def __init__(self, database_url: str) -> None:
        if not database_url.startswith("postgresql+psycopg://"):
            raise ValueError("XCIA2 durable runtime requires PostgreSQL")
        lowered = database_url.lower()
        forbidden = ("wallet", "xbos", "customer-channel", "customer_channel", "core-ledger")
        if any(marker in lowered for marker in forbidden):
            raise ValueError("database URL appears to target another project database")
        self.engine: Engine = create_engine(database_url, pool_pre_ping=True)
        self._session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )

    @contextmanager
    def session(self) -> Generator[Session]:
        with self._session_factory() as session:
            yield session

    def ping(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except SQLAlchemyError:
            return False

    def schema_revision(self) -> str | None:
        try:
            with self.engine.connect() as connection:
                value = connection.scalar(text("SELECT version_num FROM alembic_version"))
            return str(value) if value is not None else None
        except SQLAlchemyError:
            return None

    def dispose(self) -> None:
        self.engine.dispose()
