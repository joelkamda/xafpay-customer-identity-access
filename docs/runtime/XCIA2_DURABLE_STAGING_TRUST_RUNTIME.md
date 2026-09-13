# XCIA2 Durable Staging Trust Runtime

STATUS=XCIA2_CANDIDATE_IMPLEMENTATION

XCIA2 crosses the durability boundary intentionally deferred by XCIA1. It remains an XCIA-owned,
staging-capable trust substrate and does not implement public customer login or a real external
identity provider.

## Durable XCIA-owned state

XCIA2 persists only XCIA trust state in PostgreSQL:

- pairwise opaque external customer subjects;
- server-side authentication sessions;
- rotating refresh-family verification state;
- session and refresh-family revocation state;
- bounded assertion replay/JTI state;
- public signing-key metadata and lifecycle state;
- security-event state required by trust controls.

Session defaults preserve the frozen XCIA0/XCIA1 baseline:

- idle session default: 15 minutes;
- absolute session default: 8 hours;
- assertion lifetime: 5 minutes;
- clock skew: 60 seconds.

The browser does not receive API access tokens or refresh credentials. Refresh verifier material is
stored only as a nonreversible digest.

## PostgreSQL boundary

DATABASE_ENGINE=POSTGRESQL
DATABASE_OWNER=XCIA
DIRECT_WALLET_DATABASE_ACCESS=NO
DIRECT_CORE_DATABASE_ACCESS=NO
DIRECT_XBOS_DATABASE_ACCESS=NO
DIRECT_CUSTOMER_CHANNEL_DATABASE_ACCESS=NO

The migration is deterministic and downgrade-capable and creates only `xcia_*` tables.

## Staging signing authority

XCIA2 provides a staging-capable ES256 signing provider. Private key material is externally injected
and is never written to the repository, database, JWKS, logs, or test output. PostgreSQL stores only
public JWK metadata and lifecycle state.

The provider supports:

- exactly one active signing key;
- verify-only overlap during rotation;
- retirement;
- stable `kid`;
- environment and issuer binding;
- public-only JWKS;
- fail-closed behavior when signing authority is missing.

Production KMS/HSM integration remains deferred.

## Assertion issuance

Durable assertion issuance is an internal service operation and requires an active durable
authenticated session plus matching sender-key thumbprint. Required claims remain:

`iss sub aud iat nbf exp jti sid auth_time cnf.jkt`

No public endpoint accepts caller-supplied subject identity.

## Readiness

Liveness remains process-local. Readiness fails closed unless:

- configuration is valid;
- PostgreSQL is reachable;
- the expected Alembic revision is current;
- a valid active signing key is available;
- public verification material can be derived.

## Explicitly deferred

XCIA2 does not implement:

- public customer login;
- Google, Microsoft, Apple, social, password, email OTP, phone OTP, or WhatsApp login;
- Wallet customer lookup or Wallet resource authorization;
- Core, XBOS, Customer Channel, Gateway, XMP, or other-lane mutation;
- production deployment;
- production key provisioning.
