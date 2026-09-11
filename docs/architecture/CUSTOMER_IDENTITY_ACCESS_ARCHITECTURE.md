# Customer Identity & Access Architecture

## 1. Purpose

XCIA is the shared customer identity, authentication, session-trust, verified external-subject, assertion, and relying-party trust technical workstream for XafPay customer-facing services.

XCIA is owned programmatically by PCR. This document is a technical architecture front door; it is not a succession, program-governance, or cross-lane authority file.

## 2. Execution and governance model

PROGRAM_AUTHORITY_OWNER=PCR  
TECHNICAL_COORDINATION=XCIA_TECHNICAL_LEAD  
BOUNDED_EXECUTION_ENGINE=CODEX

PCR owns program governance and cross-lane authority. The XCIA technical lead coordinates bounded technical execution. Codex executes only within explicit bounded instructions.

Other-lane mutation is forbidden. Cross-lane integration requires PCR handoff.

## 3. Customer authentication boundary

CUSTOMER_AUTHENTICATION=SERVER_VERIFIED  
CALLER_SUPPLIED_IDENTITY=NEVER_TRUSTED

XCIA may establish authentication trust only after server-side verification under configured provider and relying-party policy.

Authentication is not business-resource authorization.

## 4. Verified external subject model

EXTERNAL_SUBJECT_MODEL=PAIRWISE_OPAQUE_SERVER_ISSUED_EXTERNAL_CUSTOMER_SUBJECT

The external subject:
- is server issued after verified authentication;
- is opaque and non-semantic;
- is pairwise to the governed relying-party trust context;
- contains no PII;
- is not an email address or phone number;
- is not an XBOS party id;
- is not a Wallet id;
- is not a payment account;
- is not economic authority;
- is not Wallet ownership proof.

## 5. Wallet integration boundary

Initial relying API: `WALLET_API`.

Semantic flow:

BROWSER  
-> WALLET_WEB_BFF  
-> XCIA  
-> VERIFIED_PAIRWISE_EXTERNAL_SUBJECT  
-> SHORT_LIVED_WALLET_API_ASSERTION  
-> WALLET_API  
-> AuthenticatedPrincipal(external_identity_ref)  
-> WalletCustomerRepository.by_external_identity_ref  
-> WalletCustomer  
-> WALLET_RESOURCE_AUTHORIZATION

WALLET_AUTH_PORT_CONTRACT_DELTA_REQUIRED=NO  
WALLET_PRODUCTION_AUTH_ADAPTER_REQUIRED=YES  
WALLET_CUSTOMER_MAPPING_OWNER=WALLET  
WALLET_RESOURCE_AUTHORIZATION_OWNER=WALLET

XCIA authentication is input to Wallet authorization; it never replaces Wallet authorization.

## 6. Customer Channel separation

Customer Channel remains separate and owns channel entry, transport, conversation orchestration, channel-session context, server-resolved channel subject provenance, and customer presentation.

CUSTOMER_CHANNEL_GLOBAL_AUTH_ISSUER=NO

Existing Customer Channel artifacts must not be repurposed as XCIA credentials.

Forbidden:
- CR1 entry token used as XCIA auth token;
- CR3 identity binding reference used as XCIA bearer;
- Channel internal session used as a global XCIA session.

## 7. XMP separation

XMP administrator/operator identity and XCIA customer identity are separate authority domains.

SHARED_AUTHORITY=NO  
SHARED_LOGICAL_IDENTITY_MASTER=NO

## 8. XBOS, Core, and Gateway non-authority

XCIA does not own:
- XBOS party master;
- XBOS commercial/customer resource authorization;
- Core monetary, ledger, or economic truth;
- Gateway provider execution;
- payment authority;
- merchant truth.

## 9. Transport architecture

DESIGN_BASELINE=BFF_SERVER_SIDE_SESSION  
LOGIN_HANDOFF=AUTHORIZATION_CODE_WITH_PKCE_STYLE_LOGIN_HANDOFF  
API_ASSERTION=SHORT_LIVED_AUDIENCE_BOUND_ASYMMETRICALLY_SIGNED  
SENDER_CONSTRAINT_TARGET=DPOP

BROWSER_DIRECTLY_HOLDS_API_ACCESS_TOKEN=NO  
BROWSER_DIRECTLY_HOLDS_REFRESH_TOKEN=NO  
BROWSER_CREDENTIAL=OPAQUE_HIGH_ENTROPY_SERVER_SIDE_SESSION_REFERENCE

Cookie baseline:
- HttpOnly;
- Secure;
- `__Host-` prefix;
- Path=/;
- no Domain attribute.

Required protections:
- CSRF protection;
- exact Origin validation;
- no wildcard CORS;
- trusted Host allowlist;
- session-fixation defense;
- session rotation;
- logout revocation.

## 10. Key and trust architecture

ASYMMETRIC_SIGNING=REQUIRED  
SIGNING_ALGORITHM_DEFAULT=ES256  
MANAGED_KEY_CUSTODY_TARGET=KMS_HSM_OR_EQUIVALENT_SECURE_SERVICE  
PUBLIC_KEY_DISTRIBUTION=EXACT_CONFIGURED_READ_ONLY_JWKS

Forbidden:
- symmetric shared secret with Wallet;
- private signing key in source;
- private signing key in browser;
- private signing key plaintext in database;
- private signing key shared with Wallet;
- token-supplied JWKS URL trust;
- unknown `kid`;
- wildcard audience;
- `alg=none`.

Default access assertion maximum TTL: 5 minutes.  
Default auth-session idle timeout: 15 minutes.  
Default auth-session absolute maximum: 8 hours.  
Maximum allowed clock skew: 60 seconds.

## 11. Environment isolation

ENVIRONMENT_ISOLATION=MANDATORY  
CROSS_ENVIRONMENT_ACCEPTANCE=DENY

Production and staging do not share:
- signing keys;
- subject namespaces;
- session stores.

Issuer model:
`urn:xafpay:customer-auth:<environment>`

Initial Wallet API audience:
`urn:xafpay:wallet-api:<environment>`

## 12. Future runtime components

Subject to separate PCR implementation authority, future XCIA runtime components may include:
- server-side authentication session service;
- customer authentication provider adapter;
- login handoff endpoints;
- pairwise external-subject mapping service;
- short-lived assertion issuer;
- managed signing-key integration;
- exact configured read-only JWKS publication;
- session rotation and revocation services;
- logout and logout-all handling;
- relying-party registration and trust metadata;
- authentication security audit;
- Wallet BFF relying-party integration support.

No runtime component is authorized by this foundation correction.
