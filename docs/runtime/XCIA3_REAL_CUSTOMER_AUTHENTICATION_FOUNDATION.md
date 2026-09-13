# XCIA3 real customer authentication foundation

XCIA3 adds a verifier-only, six-digit XafPay login PIN upstream of the frozen XCIA2
trusted-session and assertion boundary. Phone identifiers are accepted only as normalized
E.164 input, then converted to purpose-separated keyed opaque digests. They are never used
as XCIA subjects or assertion subjects.

The implementation uses Scrypt with a per-credential random salt and a server-side root
credential-secret interface. No secret value, PIN, third-party financial PIN, real phone
provider integration, or provider secret is included. The only provider is a deterministic
test/staging fake; it refuses production construction.

Enrollment, recovery, and new-device step-up require phone-possession proof. Login failures
are generic and account, device, and IP controls use only durable opaque digests. Successful
authentication composes the existing XCIA2 durable subject and session stores; existing ES256
assertion and `cnf.jkt` sender-binding contracts are unchanged.
