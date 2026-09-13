from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PIN_PATTERN = re.compile(r"^[0-9]{6}$")
SCRYPT_N = 32768
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
SALT_LENGTH = 16


def require_pin(value: str) -> None:
    if PIN_PATTERN.fullmatch(value) is None:
        raise ValueError("PIN must contain exactly six digits")


@dataclass(frozen=True)
class CredentialSecrets:
    root_secret: bytes

    def __post_init__(self) -> None:
        if len(self.root_secret) < 32:
            raise ValueError("credential root secret must be at least 32 bytes")

    def derive(self, purpose: str) -> bytes:
        return hmac.new(self.root_secret, purpose.encode("ascii"), hashlib.sha256).digest()

    def opaque_digest(self, purpose: str, value: str) -> str:
        return hmac.new(self.derive(purpose), value.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_phone(value: str) -> str:
    if re.fullmatch(r"\+[1-9][0-9]{7,14}", value) is None:
        raise ValueError("phone identifier must be normalized E.164")
    return value


def _prehash(pin: str, secrets: CredentialSecrets) -> bytes:
    require_pin(pin)
    return hmac.new(
        secrets.derive("xcia3/pin-prehash"),
        pin.encode("ascii"),
        hashlib.sha256,
    ).digest()


def create_verifier(pin: str, secrets: CredentialSecrets) -> str:
    salt = os.urandom(SALT_LENGTH)
    derived = Scrypt(
        salt=salt, length=SCRYPT_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    ).derive(_prehash(pin, secrets))
    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
    encoded_derived = base64.urlsafe_b64encode(derived).decode("ascii")
    return f"scrypt-v1${encoded_salt}${encoded_derived}"


def verify_pin(pin: str, verifier: str, secrets: CredentialSecrets) -> bool:
    try:
        version, encoded_salt, encoded_derived = verifier.split("$")
        if version != "scrypt-v1":
            return False
        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        expected = base64.urlsafe_b64decode(encoded_derived.encode("ascii"))
        actual = Scrypt(
            salt=salt, length=SCRYPT_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
        ).derive(_prehash(pin, secrets))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
