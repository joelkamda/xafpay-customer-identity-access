from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from xcia.persistence import XciaDatabase
from xcia.ports import JwksProvider, SigningKeyProvider


class DurableReadiness(Protocol):
    def is_ready(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class DurableReadinessProbe:
    database: XciaDatabase
    signing_keys: SigningKeyProvider
    jwks: JwksProvider
    expected_revision: str

    def is_ready(self) -> bool:
        if not self.database.ping():
            return False
        if self.database.schema_revision() != self.expected_revision:
            return False
        try:
            self.signing_keys.active_signing_key()
            public_keys = tuple(self.jwks.public_jwks())
        except (RuntimeError, ValueError):
            return False
        return len(public_keys) > 0
