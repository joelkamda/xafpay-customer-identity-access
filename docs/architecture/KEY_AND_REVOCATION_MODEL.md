# Key and Revocation Model

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Signing baseline

KEY_TYPES=ASYMMETRIC_SIGNING_ONLY_FOR_XCIA_ASSERTIONS  
ASYMMETRIC_SIGNING=REQUIRED  
SIGNING_ALGORITHM_DEFAULT=ES256  
SHARED_SYMMETRIC_SIGNING_SECRET=FORBIDDEN  
PRIVATE_KEY_CUSTODY_TARGET=KMS_OR_HSM_CLASS  
PRIVATE_KEY_PUBLICATION=FORBIDDEN  
PUBLIC_TRUST_DISTRIBUTION=READ_ONLY_JWKS  
KID_REQUIRED=YES

Forbidden:
- private signing key in source;
- private signing key in browser;
- private signing key plaintext in database;
- private signing key shared with Wallet;
- token-supplied JWKS URL trust;
- `alg=none`;
- unknown `kid`.

No signing key exists in this foundation repository.

## V1 signing-key lifecycle

The signing-key lifecycle must support:

GENERATED_OR_PROVISIONED  
-> ACTIVE_SIGNING  
-> VERIFY_ONLY_OVERLAP  
-> RETIRED

Only `ACTIVE_SIGNING` keys may mint new assertions.

`VERIFY_ONLY_OVERLAP` keys may verify still-valid assertions issued before rotation.

`RETIRED` keys must not sign new assertions.

## Key rotation

KEY_ROTATION_SUPPORTED=YES  
PLANNED_ROTATION=YES  
INCIDENT_DRIVEN_ROTATION=YES  
ENVIRONMENT_SPECIFIC_KEYS=YES  
CROSS_ENVIRONMENT_KEY_REUSE=FORBIDDEN  
FIXED_ROTATION_CADENCE=DEFERRED_TO_RUNTIME_SECURITY_POLICY  
UNKNOWN_KID=DENY

No fixed rotation interval is frozen by XCIA0.

Rotation must preserve sufficient verification overlap for still-valid assertions issued by the previous signing key.

NEW_ASSERTIONS_AFTER_ROTATION=SIGNED_BY_CURRENT_ACTIVE_KEY

## Key compromise and emergency revocation

If a signing key is suspected or confirmed compromised:

NEW_SIGNING_WITH_COMPROMISED_KEY=FORBIDDEN  
KEY_STATE=REVOKED_OR_RETIRED_FROM_TRUST_AS_SECURITY_POLICY_REQUIRES  
JWKS_TRUST_STATE=UPDATED_BY_AUTHORIZED_XCIA_RUNTIME_CONTROL  
NEW_ACTIVE_KEY=REQUIRED_BEFORE_NORMAL_ISSUANCE_RESUMES

There is no fallback to an unapproved algorithm or shared symmetric secret.

## Revocation model

XCIA distinguishes:

A. `SESSION_REVOCATION`  
B. `REFRESH_FAMILY_REVOCATION`  
C. `SIGNING_KEY_REVOCATION_OR_RETIREMENT`  
D. `SHORT_LIVED_ACCESS_ASSERTION_EXPIRY`

ACCESS_ASSERTION_LIFETIME_DEFAULT=5_MINUTES

Revoking a session or refresh family prevents future assertion issuance from that authority chain.

Already-issued assertions remain bounded by:
- signature validity;
- exact issuer;
- exact audience;
- time claims;
- sender constraint;
- signing-key trust state;
- authoritative `sid` revocation state where available.

UNIVERSAL_PERMANENT_TOKEN_BLACKLIST=NOT_REQUIRED

## Environment isolation

ENVIRONMENT_KEY_ISOLATION=REQUIRED  
CROSS_ENVIRONMENT_KEY_REUSE=FORBIDDEN

Production and staging do not share signing keys, subject namespaces, or session stores.

## Runtime boundary

SIGNING_KEY_CREATED=NO  
JWKS_ENDPOINT_LIVE=NO  
RUNTIME_IMPLEMENTATION=NO
