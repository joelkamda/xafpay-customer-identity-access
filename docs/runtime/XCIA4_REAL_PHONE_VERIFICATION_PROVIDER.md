# XCIA4 real phone verification provider

XCIA4 adds an Infobip 2FA-over-SMS adapter behind `PhoneVerificationProviderPort`.
Infobip proves phone possession only; routine XCIA login remains the normalized phone
identifier plus the XafPay login PIN. The XCIA2 session and assertion contracts and Wallet
contracts are unchanged.

The adapter maps the provider PIN reference into XCIA's opaque challenge reference and uses
an external API-key binding for server-side requests. Production requires explicit Infobip
configuration and the external secret binding. The deterministic fake provider remains for
tests and staging composition.

No Infobip account, credential, sender, application, message template, or real phone number
was created for XCIA4-B. No SMS was sent and no provider endpoint was invoked during this
tranche: tests use an injected scripted transport. Phone-number rebinding is out of scope.
