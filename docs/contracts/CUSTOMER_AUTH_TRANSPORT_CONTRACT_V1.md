# Customer Auth Transport Contract V1

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Browser architecture

BROWSER_TO_FRONTEND=SERVER_SIDE_BFF_SESSION_MODEL  
AUTHORIZATION_HANDOFF=AUTHORIZATION_CODE_WITH_PKCE_STYLE  
API_ASSERTION=SHORT_LIVED_AUDIENCE_BOUND_ASYMMETRICALLY_SIGNED_ASSERTION  
SENDER_CONSTRAINT_TARGET=DPOP

BROWSER_DIRECT_WALLET_API_TOKEN=NO  
BROWSER_DIRECTLY_HOLDS_API_ACCESS_TOKEN=NO  
BROWSER_REFRESH_TOKEN=NO  
BROWSER_DIRECTLY_HOLDS_REFRESH_TOKEN=NO  
LOCAL_STORAGE_AUTH_TOKEN=NO  
SESSION_STORAGE_AUTH_TOKEN=NO  
BROWSER_CREDENTIAL=OPAQUE_HIGH_ENTROPY_SERVER_SIDE_SESSION_REFERENCE

## Session cookie baseline

SESSION_COOKIE_HTTPONLY=YES  
SESSION_COOKIE_SECURE=YES  
SESSION_COOKIE_HOST_PREFIX_COMPATIBLE=YES  
SESSION_COOKIE_DOMAIN=ABSENT  
SESSION_COOKIE_PATH=/  
SESSION_COOKIE_SAMESITE_BASELINE=LAX

`SameSite=Lax` is the ratified V1 default. It is not a permanent constitutional constant. Any future stricter or different policy requires explicit security review and must not silently weaken to `SameSite=None`.

## Browser request protections

CSRF_TOKEN=REQUIRED  
CSRF_PROTECTION=REQUIRED  
EXACT_ORIGIN_VALIDATION=REQUIRED  
CORS_WILDCARD=FORBIDDEN  
TRUSTED_HOST_ALLOWLIST=REQUIRED  
SESSION_FIXATION_PROTECTION=REQUIRED  
SESSION_IDENTIFIER_ROTATION_AT_AUTHENTICATION_BOUNDARY=REQUIRED  
LOGOUT_INVALIDATION=REQUIRED

## Minimum relying-party assertion claim set

The following claim set is normative. Required claims may not be silently omitted.

REQUIRED_CLAIMS=iss;sub;aud;iat;nbf;exp;jti;sid;auth_time;cnf.jkt  
REQUIRED_CLAIMS_MAY_BE_OMITTED_SILENTLY=NO

`iss` = XCIA environment-specific issuer identity.  
`sub` = opaque pairwise external customer subject.  
`aud` = exact relying-party/environment audience.  
`iat` = issuance time.  
`nbf` = not-before time.  
`exp` = expiration time.  
`jti` = unique assertion identifier.  
`sid` = server-side authentication session identifier/reference.  
`auth_time` = time of the most recent qualifying authentication event.  
`cnf.jkt` = JWK thumbprint binding for the sender-constrained assertion.

## Assertion defaults and validation baseline

SIGNING_ALGORITHM_DEFAULT=ES256  
SHARED_SYMMETRIC_SIGNING_SECRET=FORBIDDEN  
ACCESS_ASSERTION_LIFETIME_DEFAULT=5_MINUTES  
CLOCK_SKEW_DEFAULT=60_SECONDS  
SENDER_CONSTRAINT_TARGET=DPOP  
UNKNOWN_KID=DENY  
EXACT_ISSUER_VALIDATION=REQUIRED  
EXACT_AUDIENCE_VALIDATION=REQUIRED  
ENVIRONMENT_ISOLATION=REQUIRED

These are ratified V1 defaults and are not permanent constitutional constants.

## jti / replay semantics

JTI_UNIQUE_PER_ASSERTION=YES  
JTI_REUSED_ACROSS_ASSERTIONS=NO  
JTI_SECURITY_PURPOSE=ASSERTION_INSTANCE_IDENTIFICATION_AND_REPLAY_DEFENSE

A sender-constrained assertion replayed outside its valid sender/context must be rejected.

## sid / revocation semantics

SID_REVOCATION_MODEL=REQUIRED  
REVOKED_SID_MAY_MINT_NEW_ASSERTIONS=NO  
ASSERTION_WITH_REVOKED_SID=REJECT_WHEN_REVOCATION_STATE_IS_AUTHORITATIVELY_AVAILABLE

The revocation-distribution runtime mechanism is deferred to separately authorized runtime implementation design.

## cnf.jkt / DPoP binding

DPOP_PROOF_KEY_MATCHES_CNF_JKT=REQUIRED  
CNF_JKT_MISMATCH=DENY  
MISSING_REQUIRED_SENDER_CONSTRAINT=DENY  
CALLER_SUPPLIED_UNVERIFIED_CNF_JKT=FORBIDDEN

## Wallet/economic claim prohibition

The shared XCIA assertion must not embed XCIA-owned Wallet roles, capabilities, permissions, balances, resource grants, transfer authority, payment authority, or economic authority.

XCIA_CUSTOMER_AUTHENTICATION_IS_RESOURCE_AUTHORIZATION=NO  
XCIA_AUTHENTICATION_IS_ECONOMIC_AUTHORITY=NO

## Runtime boundary

RUNTIME_IMPLEMENTATION=NO  
TOKEN_ISSUER_LIVE=NO
