# Session and Subject Model

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Server-side authentication session

SERVER_SIDE_SESSION=REQUIRED  
IDLE_SESSION_DEFAULT=15_MINUTES  
ABSOLUTE_SESSION_DEFAULT=8_HOURS  
SESSION_FIXATION_PROTECTION=REQUIRED  
SESSION_IDENTIFIER_ROTATION_AT_AUTHENTICATION_BOUNDARY=REQUIRED  
LOGOUT_INVALIDATION=REQUIRED

The browser holds only an opaque reference to server-side session state.

BROWSER_REFRESH_TOKEN_STORAGE=FORBIDDEN  
BROWSER_DIRECT_REFRESH_TOKEN=FORBIDDEN

A server-side authentication session is an XCIA trust artifact. It is not Wallet authorization state and it is not a Customer Channel global session.

## Rotating refresh family

Where refresh capability is required by a later authorized runtime design:

REFRESH_MODEL=SERVER_SIDE_ROTATING_REFRESH_FAMILY  
STATIC_REUSABLE_REFRESH_CREDENTIAL=FORBIDDEN  
REFRESH_ROTATION_ON_USE=REQUIRED  
REFRESH_FAMILY_IDENTIFIER=REQUIRED  
REFRESH_REUSE_DETECTION=REQUIRED  
DETECTED_REUSE_ACTION=REVOKE_ASSOCIATED_REFRESH_FAMILY_AND_SESSION

XCIA0 defines the security semantics only; it does not implement refresh runtime behavior.

## sid revocation semantics

`sid` identifies the server-side authentication session context from which an assertion was issued.

SID_REVOCATION_MODEL=REQUIRED  
LOGOUT=REVOKE_SESSION_SID  
SECURITY_TERMINATION=MAY_REVOKE_SESSION_SID  
REFRESH_REUSE_DETECTION_ACTION=REVOKE_ASSOCIATED_SESSION_SID  
REVOKED_SID_MAY_MINT_NEW_ASSERTIONS=NO  
ASSERTION_WITH_REVOKED_SID=REJECT_WHEN_REVOCATION_STATE_IS_AUTHORITATIVELY_AVAILABLE  
REVOCATION_DISTRIBUTION_RUNTIME_MECHANISM=DEFERRED_TO_RUNTIME_IMPLEMENTATION_DESIGN

Revoking a session prevents future assertion issuance from that session authority chain.

## jti and replay semantics

JTI_UNIQUE_PER_ASSERTION=YES  
JTI_REUSED_ACROSS_ASSERTIONS=NO  
JTI_PREDICTABLE=NO_REQUIRED  
JTI_SECURITY_PURPOSE=ASSERTION_INSTANCE_IDENTIFICATION_AND_REPLAY_DEFENSE  
JTI_GLOBAL_PERMANENT_LEDGER=NOT_REQUIRED  
JTI_LONG_TERM_RETENTION=NOT_REQUIRED

A sender-constrained assertion replayed outside its valid sender/context must be rejected.

A later runtime may use bounded replay-state retention consistent with assertion lifetime and security requirements.

## cnf.jkt sender binding

`cnf.jkt` is the JWK thumbprint of the key to which the assertion is sender constrained.

DPOP_PROOF_KEY_MATCHES_CNF_JKT=REQUIRED  
CNF_JKT_MISMATCH=DENY  
MISSING_REQUIRED_SENDER_CONSTRAINT=DENY  
CALLER_SUPPLIED_UNVERIFIED_CNF_JKT=FORBIDDEN

Possession of an otherwise valid assertion is insufficient when the relying-party contract requires sender constraint.

## External customer subject summary

EXTERNAL_SUBJECT_MODEL=PAIRWISE_OPAQUE_SERVER_ISSUED_EXTERNAL_CUSTOMER_SUBJECT

The verified external customer subject is server issued, opaque, non-PII, and pairwise to the relying-party/environment trust context. Detailed subject stability and explicit exclusions are defined in `docs/contracts/EXTERNAL_CUSTOMER_SUBJECT_CONTRACT_V1.md`.

## Assertion/session defaults

ACCESS_ASSERTION_LIFETIME_DEFAULT=5_MINUTES  
CLOCK_SKEW_DEFAULT=60_SECONDS

These are ratified V1 defaults, not permanent constitutional constants.

RUNTIME_IMPLEMENTATION=NO
