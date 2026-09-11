# Browser Security Model

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Browser/session baseline

BFF_SERVER_SIDE_SESSION=REQUIRED  
AUTHORIZATION_CODE_WITH_PKCE_STYLE_LOGIN_HANDOFF=REQUIRED  
BROWSER_DIRECT_API_ACCESS_TOKEN=NO  
BROWSER_DIRECT_REFRESH_TOKEN=NO

The browser holds only:

`OPAQUE_HIGH_ENTROPY_SERVER_SIDE_SESSION_REFERENCE`

The browser session credential is server-side backed and is not a Wallet API bearer credential.

## Session cookie baseline

SESSION_COOKIE_HTTPONLY=YES  
SESSION_COOKIE_SECURE=YES  
SESSION_COOKIE_HOST_PREFIX_COMPATIBLE=YES  
SESSION_COOKIE_DOMAIN=ABSENT  
SESSION_COOKIE_PATH=/  
SESSION_COOKIE_SAMESITE_BASELINE=LAX

The ratified V1 default is `SameSite=Lax`.

This default is not a permanent constitutional constant. A future stricter or different cookie policy requires explicit security review and must not silently weaken to `SameSite=None`.

## Browser-storage prohibitions

AUTH_TOKEN_IN_localStorage=FORBIDDEN  
AUTH_TOKEN_IN_sessionStorage=FORBIDDEN  
REFRESH_TOKEN_IN_localStorage=FORBIDDEN  
REFRESH_TOKEN_IN_sessionStorage=FORBIDDEN  
BROWSER_REFRESH_TOKEN_STORAGE=FORBIDDEN

## Request-security requirements

CSRF_TOKEN=REQUIRED  
CSRF_PROTECTION=REQUIRED  
EXACT_ORIGIN_VALIDATION=REQUIRED  
CORS_WILDCARD=FORBIDDEN  
TRUSTED_HOST_ALLOWLIST=REQUIRED  
SESSION_FIXATION_PROTECTION=REQUIRED  
SESSION_IDENTIFIER_ROTATION_AT_AUTHENTICATION_BOUNDARY=REQUIRED  
LOGOUT_INVALIDATION=REQUIRED

The browser must never become the custody location for XCIA private signing keys or long-lived Wallet API bearer credentials.

RUNTIME_IMPLEMENTATION=NO
