# External Customer Subject Contract V1

STATUS=XCIA0_TECHNICAL_FOUNDATION

## Subject definition

SERVER_ISSUED=YES  
CALLER_SUPPLIED=NO  
OPAQUE=YES  
NON_PII=YES  
PAIRWISE=YES  
STABLE_ACROSS_SESSIONS_FOR_SAME_RELYING_PARTY_AND_ENVIRONMENT=YES  
STABLE_ACROSS_ALL_RELYING_PARTIES=NO_REQUIRED  
STABLE_ACROSS_ENVIRONMENTS=NO_REQUIRED

EXTERNAL_SUBJECT_MODEL=PAIRWISE_OPAQUE_SERVER_ISSUED_EXTERNAL_CUSTOMER_SUBJECT

The subject is issued only after server-verified authentication and is scoped to the governed relying-party/environment trust context.

## Explicit subject exclusions

The external customer subject must not itself be:

- email address;
- phone number;
- human name;
- display name;
- XBOS Party ID;
- Wallet ID;
- customer database ID;
- merchant ID;
- payment account;
- financial account;
- economic account;
- provider credential.

NAME_AS_SUBJECT=FORBIDDEN  
MERCHANT_ID_AS_SUBJECT=FORBIDDEN  
FINANCIAL_ACCOUNT_AS_SUBJECT=FORBIDDEN

EXTERNAL_SUBJECT_CONTAINS_PII=NO  
EXTERNAL_SUBJECT_IS_EMAIL=NO  
EXTERNAL_SUBJECT_IS_PHONE=NO  
EXTERNAL_SUBJECT_IS_XBOS_PARTY=NO  
EXTERNAL_SUBJECT_IS_WALLET_ID=NO  
EXTERNAL_SUBJECT_IS_PAYMENT_ACCOUNT=NO  
EXTERNAL_SUBJECT_IS_ECONOMIC_AUTHORITY=NO  
EXTERNAL_SUBJECT_IS_WALLET_OWNERSHIP_PROOF=NO

## Wallet compatibility boundary

VERIFIED_XCIA_SUB  
-> AuthenticatedPrincipal(external_identity_ref)  
-> WalletCustomer mapping  
-> Wallet-owned authorization

WALLET_AUTH_PORT_CONTRACT_DELTA_REQUIRED=NO  
PRODUCTION_AUTH_ADAPTER_REQUIRED=YES  
XCIA_OWNS_WALLET_CUSTOMER_MAPPING=NO  
XCIA_OWNS_WALLET_RESOURCE_AUTHORIZATION=NO  
XCIA_OWNS_WALLET_ROLE=NO  
XCIA_OWNS_WALLET_PERMISSION=NO  
XCIA_OWNS_BALANCE_AUTHORITY=NO  
XCIA_OWNS_TRANSFER_AUTHORITY=NO

No Wallet role, capability, permission, resource grant, balance, transfer authority, or economic claim may be inserted into the shared XCIA subject or assertion contract.

RUNTIME_IMPLEMENTATION=NO
