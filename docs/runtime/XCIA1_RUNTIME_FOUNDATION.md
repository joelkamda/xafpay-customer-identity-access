# XCIA1 Executable Runtime Foundation

XCIA1 materializes the PCR-accepted XCIA0 trust contracts as an executable Python 3.13 / FastAPI trust substrate.

## Included

- application factory and fail-closed configuration;
- `/health/live` and `/health/ready`;
- typed frozen-contract domain models;
- browser/session policy invariants;
- external-subject policy enforcement;
- cryptographic provider ports;
- assertion signer/verifier ports;
- session-authority ports;
- revocation and replay-defense ports;
- read-only JWKS presentation logic;
- assertion trust orchestration;
- test-only in-memory fakes and ephemeral ES256 harness.

## Explicitly not included

XCIA1 does not provide:

- a real customer login flow;
- a real identity provider;
- OIDC discovery, redirects, or callbacks;
- password, passkey, TOTP, SMS OTP, Google, Microsoft, or Apple login;
- a database or migration;
- a durable session, refresh, revocation, or identity store;
- production key custody;
- KMS or HSM integration;
- persisted or committed private keys;
- production assertion issuance;
- a production JWKS endpoint backed by real keys;
- Wallet, Customer Channel, XMP, XBOS, Core, or Gateway mutation;
- deployment or release.

PCR remains program-governance and cross-lane authority.

## Local validation

Install the project with the `dev` extra and run:

```text
python -m pytest -q
python -m ruff check .
python -m pyright
```

The service is intended to be started through an ASGI server with `xcia.app:create_app` as a factory only when complete required `XCIA_*` trust configuration is present.
