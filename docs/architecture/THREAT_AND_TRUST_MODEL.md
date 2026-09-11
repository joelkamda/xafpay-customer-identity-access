# Threat and Trust Model

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Trusted authority

XCIA trusts authentication facts only after server-side verification under configured provider and relying-party policy.

## Explicitly untrusted inputs

- caller-supplied identity identifiers;
- browser-provided authorization decisions;
- token-supplied issuer or JWKS routing;
- wildcard audiences;
- unregistered relying parties;
- cross-environment credentials or assertions;
- Customer Channel entry/session artifacts used as global credentials.

## Primary threats

- identity spoofing;
- session fixation;
- session theft;
- CSRF;
- origin confusion;
- CORS overexposure;
- bearer replay;
- audience confusion;
- issuer confusion;
- key substitution;
- unknown-key acceptance;
- algorithm downgrade;
- cross-environment trust bleed;
- subject correlation across relying parties;
- privilege transfer from authentication into business authorization.

## Trust principles

Authentication and business authorization are separate.

XCIA proves that a customer authenticated under a governed trust relationship. The relying service remains responsible for deciding what that authenticated principal may do with its resources.

Caller-supplied identity is never trusted as authentication proof.
