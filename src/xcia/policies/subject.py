from __future__ import annotations

import re
from enum import StrEnum

from xcia.domain import ExternalCustomerSubject


class SubjectRepresentation(StrEnum):
    OPAQUE = "opaque"
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    DISPLAY_NAME = "display_name"
    XBOS_PARTY_ID = "xbos_party_id"
    WALLET_ID = "wallet_id"
    CUSTOMER_DATABASE_ID = "customer_database_id"
    MERCHANT_ID = "merchant_id"
    PAYMENT_ACCOUNT = "payment_account"
    FINANCIAL_ACCOUNT = "financial_account"
    ECONOMIC_ACCOUNT = "economic_account"
    PROVIDER_CREDENTIAL = "provider_credential"


class SubjectPolicy:
    _email = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    _phone = re.compile(r"^\+?[0-9][0-9()\-\s]{6,}$")
    _reserved_prefixes = (
        "xbos:",
        "wallet:",
        "merchant:",
        "payment:",
        "financial:",
        "economic:",
        "provider:",
        "customer:",
    )

    @classmethod
    def create_server_issued_subject(
        cls,
        *,
        value: str,
        relying_party: str,
        environment: str,
        representation: SubjectRepresentation = SubjectRepresentation.OPAQUE,
    ) -> ExternalCustomerSubject:
        if representation is not SubjectRepresentation.OPAQUE:
            raise ValueError(f"{representation.value} is forbidden as an XCIA external subject")
        cls._validate_opaque_value(value)
        return ExternalCustomerSubject(
            value=value,
            relying_party=relying_party,
            environment=environment,
        )

    @classmethod
    def _validate_opaque_value(cls, value: str) -> None:
        if cls._email.fullmatch(value):
            raise ValueError("email-shaped value is forbidden as external subject")
        if cls._phone.fullmatch(value):
            raise ValueError("phone-shaped value is forbidden as external subject")
        lowered = value.lower()
        if lowered.startswith(cls._reserved_prefixes):
            raise ValueError("resource/account identifier is forbidden as external subject")
        if any(character.isspace() for character in value):
            raise ValueError(
                "human-name/display-name shaped value is forbidden as external subject"
            )
