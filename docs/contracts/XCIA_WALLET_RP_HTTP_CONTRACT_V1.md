# XCIA Wallet Relying-Party HTTP Contract V1

STATUS=POST_WR7_FL1A_CANDIDATE
RELYING_PARTY=WALLET_API
ENVIRONMENT_ISOLATION=REQUIRED
AUDIENCE_MODEL=urn:xafpay:wallet-api:<environment>

## Purpose

Materialize the existing XCIA durable session, assertion issuer, and public JWKS
capabilities as the narrow server-side HTTP trust producer consumed by Wallet
integration successors.

This contract does not grant Wallet resource authority or economic authority.

## Assertion handoff

METHOD=POST
ROUTE=/bff/relying-parties/wallet/assertion
BFF_ORIGIN_PROTECTION=REQUIRED
BFF_CSRF_PROTECTION=REQUIRED
SESSION_COOKIE=REQUIRED
SENDER_JKT=REQUIRED
ASSERTION_ISSUER=DurableAssertionIssuer
TOKEN_TYPE=DPoP
EXPIRES_IN_SECONDS=300
CALLER_SUPPLIED_SUB=FORBIDDEN
CALLER_SUPPLIED_AUDIENCE=FORBIDDEN
CALLER_SUPPLIED_WALLET_ID=FORBIDDEN
CALLER_SUPPLIED_ROLE=FORBIDDEN
CALLER_SUPPLIED_PERMISSION=FORBIDDEN
CALLER_SUPPLIED_ECONOMIC_AUTHORITY=FORBIDDEN

The route obtains `sid` only from the configured XCIA server-side session cookie.
The existing issuer must resolve an active durable session and require exact
`sender_jkt` equality with that session before minting an assertion.

The response contains exactly:

- `assertion`
- `token_type`
- `expires_in`

It must not return phone, email, name, Wallet identity, Wallet permissions,
balances, Core accounts, or transfer/economic authority.

## Assertion claims

Claims remain exactly the ratified XCIA trust set:

`iss sub aud iat nbf exp jti sid auth_time cnf.jkt`
`sub` is the opaque pairwise XCIA subject already bound to the authenticated
session. The HTTP caller cannot replace it.

`aud` is the exact configured Wallet audience for the runtime environment.
The HTTP caller cannot replace or wildcard it.

`jti` is newly minted for every assertion.

`sid`, `auth_time`, and `cnf.jkt` preserve the authenticated session trust
context.

## Public JWKS

METHOD=GET
ROUTE=/.well-known/jwks.json
PRESENTER=JwksPresenter
RESPONSE_SHAPE={"keys":[...]}

The endpoint publishes verification metadata only. Private or symmetric JWK
members are forbidden and cause fail-closed unavailability rather than output.

JWKS_CUSTOMER_AUTHENTICATION=NO
JWKS_WALLET_RESOURCE_AUTHORITY=NO
JWKS_ECONOMIC_AUTHORITY=NO

## Failure law

MISSING_SESSION=DENY
REVOKED_SESSION=DENY
EXPIRED_SESSION=DENY
SENDER_JKT_MISMATCH=DENY
ARBITRARY_AUDIENCE_SELECTION=DENY
CALLER_SUPPLIED_SUBJECT=DENY
PRIVATE_JWK_MEMBER=DENY

No fallback to phone number, device identifier, caller-supplied subject,
Wallet ID, role, permission, or economic identity is permitted.

## Runtime status

This source contract is an FL1A materialized candidate only.

XCIA_RUNTIME_DEPLOYED=NO
XCIA_RUNTIME_ACCEPTED=NO
WALLET_TRUST_ADAPTER_CONNECTED=NO
WP15_AUTH_CONNECTED=NO
REAL_CUSTOMER_LOGIN_ACCEPTED=NO
CORE_BACKED_BALANCE_VISIBLE_IN_WP15=NO
