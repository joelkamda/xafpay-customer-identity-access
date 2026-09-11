# XafPay Customer Identity & Access (XCIA)

XCIA is a **PCR-owned shared technical workstream** for customer identity, authentication, session trust, external subject issuance, relying-party trust, and related security architecture.

## Operating model

- PCR owns program governance and all cross-lane authority decisions.
- The XCIA technical lead coordinates bounded technical execution within PCR authority.
- Codex is the bounded execution engine.
- This repository contains XCIA technical architecture, technical contracts, and—when separately authorized—runtime, tests, and deployment artifacts.
- Other-lane mutation is forbidden.
- Cross-lane integration requires an explicit PCR handoff.

XCIA is not an autonomous program-governance lane. This repository is not the canonical source of program authority.

## Technical authority boundaries

XCIA does not own:
- a universal customer master;
- KYC master authority;
- Wallet customer-resource authorization, balance truth, account ownership, or debit authority;
- XBOS customer/resource authorization;
- payment authority;
- economic authority;
- Core monetary or ledger truth;
- Gateway provider execution;
- Customer Channel orchestration or global channel authority;
- XMP administrator/operator identity.

XCIA provides technical customer authentication and identity/session trust to explicitly governed relying parties.

## Current foundation state

This technical foundation contains architecture and contracts only.

RUNTIME_IMPLEMENTATION=NO  
SOURCE_CODE=NO  
DATABASE=NO  
MIGRATION=NO  
SIGNING_KEYS=NO  
JWT_ISSUANCE=NO  
SESSION_RUNTIME=NO  
PROVIDER_INTEGRATION=NO
