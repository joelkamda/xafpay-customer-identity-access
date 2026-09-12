from __future__ import annotations

from dataclasses import dataclass

from xcia.ports.crypto import JwksProvider


class PrivateKeyExposureError(ValueError):
    pass


_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


@dataclass(frozen=True, slots=True)
class JwksPresenter:
    provider: JwksProvider

    def document(self) -> dict[str, list[dict[str, object]]]:
        public_keys: list[dict[str, object]] = []
        for supplied in self.provider.public_jwks():
            key = dict(supplied)
            leaked = _PRIVATE_JWK_MEMBERS.intersection(key)
            if leaked:
                raise PrivateKeyExposureError(
                    f"JWKS provider exposed private/symmetric members: {sorted(leaked)}"
                )
            public_keys.append(key)
        return {"keys": public_keys}
