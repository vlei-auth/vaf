# vLEI Authenticator Framework (VAF) — Version 1.0

*Editor's Draft — 1 November 2026*

**Specification identifier:** VAF-1.0  
**Editor's Draft URL:** https://vlei-auth.github.io/vaf/  
**Short name:** VAF  
**Status:** Editor's Draft  
**Editors:**
  * Fan Dang (ACentauri Technology Limited)

**Companion protocol:** [VCAP 1.0 — vLEI Key Authenticator Protocol](https://vlei-auth.github.io/vcap/)

## Abstract

This specification defines an interoperable hardware-backed authenticator model for KERI-based identifiers used in vLEI applications. VAF specifies the participants and trust boundaries, minimum authenticator security guarantees, supported KERI operations, enterprise authorization semantics, attestation and state evidence, lifecycle and loss-recovery obligations, and conformance profiles. The companion protocol **VCAP 1.0** defines authenticator commands, exact encodings, responses and transports.

## Status of this document

This is an unpublished **Editor's Draft** for public review. It describes a concrete initial security architecture and lists open requirements in Section 13. Independent security review, interoperability testing, governance review and standardization are pending; the MUST and SHALL requirements below are proposed conformance requirements for that review.

## 1. Introduction

### 1.1 Design goals

An employee receives an enterprise-issued physical key and uses it over USB or NFC, from a wallet or from an enterprise web page through the browser's WebAuthn API, to operate KERI identities and interact with vLEI business applications, while the identity-control private keys stay inside the authenticator. Any KERI client that implements VCAP and obtains enterprise Tickets can use the same authenticator.

A conforming deployment SHOULD keep the following responsibilities separate: the authenticator proves possession of protected KERI keys and enforces local signing restrictions; the enterprise authorizes each signing operation through a Ticket; the KERI infrastructure determines network-accepted key state; an ACDC/vLEI verifier determines credential validity; and the relying party's policy decision point (PDP) makes the final business authorization decision.

### 1.2 Scope

VAF specifies (a) roles and architectural boundaries; (b) authenticator-level identity and signing properties; (c) device state and evidence semantics; (d) enterprise policy binding; (e) platform, issuer and verifier responsibilities; (f) security and privacy guarantees and their limits; and (g) conformance requirements.

VCAP specifies command values, parameters, error semantics, framing and transport bindings. KERI event serialization, CESR encoding, ACDC schemas, IPEX messages, witness infrastructure and OIDC session tokens are governed by their respective specifications.

### 1.3 Conformance terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, **SHOULD NOT** and **MAY**, when capitalized, are to be interpreted as described by BCP 14 (RFC 2119 and RFC 8174). A normative requirement applies to the relevant conformance class and declared profile. Examples, explanatory notes and candidate profiles are informative unless explicitly marked otherwise.

### 1.4 Relationship to existing standards

VAF builds on the following external systems and uses their definitions as published:

| System | Authority | VAF integration boundary |
| --- | --- | --- |
| **KERI** | KERI specification and compatible implementation profile | AIDs, key events, current/next keys, commitments, sequence numbers, prior event links |
| **CESR / SAID** | Relevant KERI-family specifications | External signature attachments and content-addressed identifiers |
| **ACDC / IPEX** | Relevant ACDC and IPEX specifications | Credentials, disclosure and exchange handled by wallet/agent/verifier |
| **vLEI** | GLEIF vLEI Ecosystem Governance Framework (EGF) | Credential types, issuance, revocation, legal/role trust chain |
| **VCAP** | Companion device protocol | Exact command values, wire structures, transport, PIN and state encodings |
| **CTAP 2.3 / WebAuthn** | FIDO Alliance, W3C | Transports, PIN protocol, generic-client sharing and the WebAuthn route used by VCAP |

VAF conformance is a claim about this specification only. GLEIF qualification and FIDO certification are separate programs with their own requirements.

## 2. Actors and trust boundaries

### 2.1 Actors

- **Authenticator:** an external hardware unit holding its attestation identity and exactly four independently stateful key slots in the initial profile.
- **Platform / wallet:** an untrusted client of the authenticator, responsible for preparing the actual message, maintaining an Outbox and contacting external services.
- **Manufacturer:** generates the device attestation identity and issues its manufacturer certificate chain.
- **Enterprise administrator:** verifies manufactured device identity, binds the tenant and enterprise root, and provisions the enterprise-signed `TrustConfig`.
- **Ticket issuer:** validates device state and the requested action, persists the message, and signs a single-use Ticket that authorizes one digest-bound cryptographic operation.
- **KERI agent / infrastructure:** validates and publishes key events, collects witness receipts and tracks network state; may provide Signify/KERIA-compatible application functionality.
- **Credential verifier:** validates the ACDC/vLEI issuance chain, holder proof, disclosure, status and required anchoring.
- **Relying party / PDP:** applies current business roles, resource policy, revocation, session state and risk constraints.

### 2.2 Trust assumptions

The platform is treated as potentially malicious: it can observe, block, replay or reorder messages, request signatures, and withhold responses. A Ticket authorizes one signature kind, one signing key (through `KeyRef`), one exact message digest and length, and one value of the slot's signature counter, so it is usable for exactly one signature. The Ticket issuer is trusted to approve operation content; producing a signature additionally requires the private key inside the authenticator, a PIN-authorized token and a fresh touch. A touch establishes fresh user presence (**UP**).

The initial profile protects keys against extraction through the authenticator interface. Protection against invasive physical extraction, fault injection, side-channel analysis and nonvolatile-memory rollback is a product property.

### 2.3 Architectural processing flow

1. The platform sends the message to the Ticket issuer. The issuer verifies device enrollment, the requested KERI/business operation and the slot head and signature counter it has archived, durably stores the original message and signs a Ticket for the slot's next counter value. This step does not need the authenticator.
2. The platform opens a VCAP transport and obtains a PIN-authorized token while the user enters the PIN.
3. The platform durably stores the message in its Outbox and sends `Sign` or the upload sequence.
4. The authenticator checks the Ticket, signature counter, message digest and length, key binding, KERI or other message constraints, and fresh UP; it commits the counter and any KEL state transition atomically and then releases the signature.
5. The platform independently verifies the returned signature; enterprise systems archive it and separately determine network acceptance and business authorization.

A normal signature therefore takes one business exchange with the authenticator. The authenticator enforces the KEL head, so a Ticket based on an outdated head yields no signature. When the issuer has no archived head for the slot, when an earlier outcome is unknown, or when policy requires it, the platform first calls `GetState` with an issuer-generated, single-use challenge and submits the resulting `StateProof` with the message (VCAP §12.2).

Status reporting MUST distinguish the stages **device signed**, **enterprise archived**, **network accepted**, **credential verified** and **business authorized**.

## 3. Authenticator and identity model

### 3.1 Device binding

Each authenticator MUST have a protected device attestation identity. The initial profile provisions an Ed25519 attestation key pair and a manufacturer certificate chain; the chain is delivered at enrollment, outside the runtime `GetState` response. The enterprise MUST verify the chain and bind the attestation public key to its enrollment record before accepting state evidence, and thereafter verifies each `StateProof` with that enrolled public key.

The initial profile MUST implement a one-time enterprise binding. `BindEnterprise` fixes a `tenant` and `enterpriseRoot` for the physical device for its entire life, and a reset MUST preserve that binding. Moving a device to another enterprise requires replacing the device.

### 3.2 Slots and owner classes

VCAP 1.0 defines exactly four slots (`0..3`), each with owner `CLIENT=1` or `WORK=2` and phase `UNUSED`, `CREATED` or `ACTIVE`. Any mix of owners is permitted, including four WORK slots. Once assigned, a slot keeps its identity until the next reset epoch. Owner names denote **cryptographic operation profiles**; a natural person's legal identity is established by validated vLEI credentials bound to the AID (Section 7.2).

| Owner | Purpose | Allowed operation kinds |
| --- | --- | --- |
| `CLIENT` | Client AID controlling a KERIA agent | `ICP`, `IXN`, `AGENT` |
| `WORK` | Work AID used for vLEI credentials and exchanges | `ICP`, `IXN`, `ROT`, `EXN`, `RPY` |

Each slot holds one single-key, non-delegated KERI AID whose keys are all generated inside the authenticator. The initial profile advertises exactly the operations in the table above. Group (multi-signature) AIDs, delegated inception and rotation, and CLIENT rotation are candidate extensions (Sections 11.2 and 13).

### 3.3 Key ownership and commitments

The authenticator MUST generate current and next private signing keys inside its trust boundary; VCAP provides no command that imports, exports or accepts an external private key. On KERI inception, the authenticator checks that the event's current key and next-key commitment match its own generated keys. Before a rotation, `PrepareRotation` generates the new next key inside the device. On rotation, the authenticator signs with the previously committed `old.next` private key and checks that the event commits to the prepared new next key. Every key and commitment in a signed event is therefore an authenticator-generated key.

The initial profile constrains `icp` and `rot` to one current key (`kt="1"`), one next-key commitment (`nt="1"`), and BLAKE3-256 next-key digests. This is a subset of KERI.

### 3.4 KERI event head and fork prevention

Each ACTIVE slot MUST keep a durable head describing its most recently committed event. An `ICP` MUST have `s=0` and `d=i`; an `IXN` or `ROT` MUST have sequence `latest.seq + 1`, `p` equal to `latest.said`, and `i` equal to the slot AID. The authenticator MUST update the slot head atomically before returning the signature of a KEL event. As a result, the authenticator's interface advances each slot's KEL strictly one event at a time and never produces two events with the same sequence number, given intact persistent storage. Network acceptance of each event is established separately by the KERI infrastructure (Section 6.4).

### 3.5 Employee AIDs and legal-entity AIDs

AIDs held in the authenticator's slots belong to the employee. They are distinct from the legal entity's AID and from any group AID in which the employee participates. Authority over the legal entity's AID is defined by that AID's own key state and by the vLEI EGF; an employee's WORK AID and any role credential issued to it convey exactly the authority stated in that credential.

## 4. Authenticator lifecycle

### 4.1 Device lifecycle

The lifecycle states are `STOCK_UNBOUND`, `ENTERPRISE_BOUND`, `PERSONALIZED_NO_PIN`, `PIN_READY` and `RECOVERY_REQUIRED`. Transitions are:

```text
Manufacturing                                   → STOCK_UNBOUND
STOCK_UNBOUND + BindEnterprise + fresh UP       → ENTERPRISE_BOUND
ENTERPRISE_BOUND + Personalize(enterprise-signed TrustConfig) + fresh UP
                                                → PERSONALIZED_NO_PIN
  (PIN_READY instead, if a PIN was already set)
PERSONALIZED_NO_PIN + ClientPIN.setPIN          → PIN_READY
ENTERPRISE_BOUND | PERSONALIZED_NO_PIN | PIN_READY + Reset
  (within 10 s of power-on, 5-second hold)      → ENTERPRISE_BOUND, resetEpoch + 1
Valid reset intent record found at start-up     → ENTERPRISE_BOUND, resetEpoch + 1
Unrecognized or corrupted persistent data       → RECOVERY_REQUIRED
RECOVERY_REQUIRED + Reset (binding readable)    → ENTERPRISE_BOUND, resetEpoch + 1
```

The authenticator MUST treat missing or corrupted data in previously initialized storage as `RECOVERY_REQUIRED` and preserve that data until a Reset. In `RECOVERY_REQUIRED`, the authenticator accepts only `GetInfo`, status-mode `GetState`, `Cancel` and `Reset`. Reset destroys the unreadable data and starts a new reset epoch while keeping the enterprise binding; if the binding itself is unreadable, the device requires offline maintenance.

### 4.2 Personalization and enterprise governance

The authenticator MUST verify `TrustConfig` against the bound enterprise root, the device identifier, tenant and current reset epoch. `TrustConfig` contains an owner mask, a minimum PIN length, 1–8 role public keys with their capability masks, and the list of enterprise RP IDs allowed to use the WebAuthn route (VCAP §7.14). Personalization happens once per reset epoch; changing role keys or enterprise policy requires a Reset followed by a new Personalize. A VAF deployment MUST document the resulting emergency-revocation and service-availability procedures.

### 4.3 PIN and UP

The device MUST enforce its own PIN retry limits with durable failed-attempt accounting, and MUST receive the PIN encrypted under CTAP `pinUvAuthProtocol 2` (P-256 ECDH, HKDF-SHA-256, AES-256-CBC, HMAC-SHA-256), which VCAP `ClientPIN` uses unchanged. VCAP 1.0 uses the CTAP PIN retry and power-cycle lockout rules, and adds `READ`, `SIGN` and `MANAGE` token permissions above the CTAP permission bits. PIN-derived material and tokens MUST be discarded when the context ends. Every signature by a slot key (`Sign`, `UploadEnd`, or a signature requested through WebAuthn) MUST consume its own new user action, either a sensor press or, over NFC, the tap into the reader's field (one tap per field session); `BindEnterprise` and `Personalize` also require a touch, and `Reset` requires a 5-second hold.

Wallets present a touch as confirmation of presence. Higher assurance for message content comes from independent, trusted content confirmation outside the displayless device together with server-side approval appropriate to the transaction.

### 4.4 Reset and retirement

A physical reset MUST make the PIN record, all slot private keys (including pre-rotation historical keys) and all FIDO credentials unrecoverable, increment `resetEpoch`, remove personalized state, and retain the attestation identity and enterprise binding. The reset intent MUST survive power interruption, so that a reset interrupted after its intent record is written completes at the next start. Reset acts only on the device: the enterprise MUST separately invalidate earlier Tickets, user roles, active sessions and network identities as required (Section 9.4).

## 5. Enterprise authorization model

### 5.1 Separate cryptographic, credential and business authorization

Every signature by a slot key requires a valid Ticket. A Ticket authorizes one **specific cryptographic operation**; vLEI credentials, OIDC sessions and application permissions are separate authorization layers. A verified OOR/ECR credential with current status and a valid chain may contribute an attribute to a PDP decision.

### 5.2 TrustConfig and role capabilities

The role public keys, role identifiers and capability masks MUST be bound by a `TrustConfig` signature under the enterprise root. Each capability bit names one (owner, kind) pair. A conforming Ticket issuer MUST sign only operations whose (owner, kind) pair is in the signing role's capability mask, and the authenticator MUST independently check the capability mask for each request.

### 5.3 Ticket semantics

In VCAP 1.0, a Ticket is an enterprise role-key signature, under domain tag `VHKP-SIGN\0`, over:

```text
[version, kind, signerKeyRef, signCounter,
 originalDigest, originalLength]
```

The authenticator derives `KeyRef` from its own verified slot state: device identity, reset epoch, slot, owner and the **actual** signing public key (`old.next` for `ROT`, `current` otherwise), and compares it with `signerKeyRef`. The digest binds the Ticket to exact bytes. `signCounter` is the value the slot's persistent signature counter will take with this signature; the authenticator accepts the Ticket only when the counter currently equals `signCounter − 1`, and advances it in the same atomic commit as the signature. Each Ticket is therefore usable once, independent of any transport session, and can be obtained before the authenticator is connected.

The Ticket issuer MUST base each Ticket on reliable state evidence: a fresh `StateProof` bound to its own single-use challenge, or an archived original signature together with network-accepted head progression. It MUST persist the requested message before signing the Ticket, and check its semantics and risk. When it issues a replacement Ticket for a counter value whose earlier Ticket went unused, it treats the earlier Ticket as still usable until the counter advances. The issuer learns the counter from archived signatures, a `StateProof`, or the `signCount` of a WebAuthn response.

**Replay and time boundary:** every Ticket becomes unusable once any signature on its slot commits. A Ticket carries no time limit: an unused Ticket stays valid until the next signature on the slot, and the enterprise revokes it by having another signature made or by Reset. Timeliness comes from issuance-time checks and from the messages themselves (the KEL head binding, `dt` in `exn`/`rpy`, `expires` in `AGENT`). Recipients SHOULD still enforce request-level anti-replay as defense in depth.

### 5.4 Operation categories

The baseline capability registry consists of the six VCAP signing kinds (`ICP`, `IXN`, `ROT`, `EXN`, `RPY`, `AGENT`) combined with the owners listed in Section 3.2 (eight valid combinations, VCAP Appendix B). VAF defines their authorization purpose; VCAP defines the numeric values and exact validation algorithm. The `AGENT` kind signs a short-lived, domain-separated session message whose claims are limited to the Veridian read and housekeeping actions listed in VCAP §8.5.3.

### 5.5 Candidate enterprise risk profile (informative)

Candidate profile `VAF-POLICY-1` distinguishes LOW (short-lived read-only access), MEDIUM (ordinary signing and credential presentation) and HIGH (privileged operations or anchored presentations). A central PDP is the final authorization authority; a LOW read-only decision MAY be cached under an explicitly scoped, time-limited lease, and every HIGH operation receives a fresh online decision.

## 6. Signing and recovery

### 6.1 Signing protocol boundary

The authenticator receives the complete message bytes, computes their digest itself and checks it against the Ticket's digest and length, verifies KERI field and key consistency for the operation kind, and collects a fresh UP before releasing a signature. The platform MUST independently verify the returned signature over its own saved message bytes.

For KEL events, the authenticator checks the version-string size, event type, `i`, `s`, `p`, `d` format, current keys, thresholds and next-key commitment. The enterprise/KERI service MUST verify the SAID, witness receipts, delegation and network acceptance before treating the event as valid in the wider ecosystem.

### 6.2 Atomic KEL commit and response loss

For `ICP`, `IXN` and `ROT`, the device MUST atomically persist its new head (and rotated keys for `ROT`) before releasing the result. It MUST store the original signature of the latest event, and of the most recent signature of any kind, and return **that exact signature** through `Recover` when given the matching message digest.

When a response to `Sign`, `UploadEnd`, `CreateIdentity` or `PrepareRotation` is lost, the platform MUST open a new context, obtain a new challenge-bound `StateProof`, and compare the slot state with the expected result. For a committed KEL event it then calls `Recover` or retrieves archival evidence; if the head is unchanged, the enterprise decides whether to issue a new Ticket.

### 6.3 Non-KEL recovery

Every signature, including `EXN`, `RPY` and `AGENT`, advances the slot's signature counter, so a `StateProof` shows whether a Ticket was used. The authenticator keeps the most recent signature of each slot; while no later signature has been made, a lost non-KEL response is retrieved with `Recover`. Older non-KEL signatures come only from the platform Outbox and the enterprise archive. IPEX-level operation recovery (stable operation identifiers and deduplication across several messages) remains an open item (Section 13).

### 6.4 KERI network acceptance

A local commit is reported as **device signed**; witness receipts, completed delegation, KEL acceptance and business settlement are reported only from their own evidence. When an authoritative party permanently rejects a committed event and operations staff approve, the enterprise marks the slot as rejected and issues no further Tickets for it in the current reset epoch; the slot's head stays as committed, and reusing the slot requires a Reset. After a temporary failure, the enterprise redelivers the original signature.

## 7. vLEI credential interaction and presentation

### 7.1 Storage and validation boundary

The initial VAF profile protects KERI signing keys inside the authenticator. Full ACDC objects, KELs, OOR/ECR credentials, status registries and IPEX message state are held by the wallet, agent and verifier, which manage credential discovery, disclosure selection, proof-chain checking, issuance trust, revocation status and external anchoring.

### 7.2 Credential-holder proof

When ACDC/IPEX semantics allow, a presentation for a credential issued to a WORK AID MAY use an authorized device signature as holder evidence. The verifier MUST validate the purpose, verifier challenge, issuee binding, signature, the AID's KERI key state, credential status and disclosure requirements. A device signature proves control of the AID; a valid vLEI role is established by the verified credential chain.

### 7.3 IPEX integration

A WORK slot signs any `exn` message whose `i` equals the slot AID, so an off-device agent can build and exchange IPEX messages (for example `grant` and `admit`) signed by the authenticator. The enterprise validates the route, recipient and business meaning before issuing the Ticket. End-to-end IPEX conformance, replay-safe operation recovery and presentation-policy enforcement are specified by candidate profile `VAF-IPEX-1`.

### 7.4 Candidate signed/anchored presentation assurance (informative)

Candidate profile `VAF-PRES-1` lets ordinary operations use a signed holder proof and requires verified KERI anchoring for high-risk operations. Holder proof and anchor evidence are distinct outputs; a verifier reports `Anchored` only after verifying the anchor. Holder privacy, disclosure minimization and enterprise business authorization are specified separately.

## 8. Platform, verifier and PDP obligations

### 8.1 Platform

Platforms MUST submit a `StateProof` with the Ticket request whenever their knowledge of the slot head or counter is uncertain; write the message to the Outbox after receiving the Ticket and before sending `Sign`; verify the returned signature and signer key; recover lost responses through state comparison (Section 6.2); report transport success and application success separately; and clear PIN, shared secrets and tokens when the session ends. On the WebAuthn route the browser handles the PIN and token, and the message stored by the enterprise before Ticket issuance serves as the Outbox. After a transport reconnection the platform establishes a new context and token, and determines the outcome of any in-flight operation through `GetState`.

### 8.2 Ticket issuer

A Ticket issuer MUST verify enrollment, attestation public key, tenant, reset epoch, authoritative current state, role authorization, request content, message format and risk before signing a Ticket. Its state evidence is either a `StateProof` answering a single-use challenge it generated, or its archived head and signature counter (an archived original signature, or network-accepted head progression). It MUST persist an audit record and the original message before signing. Ticket issuance follows the enterprise's current permission state: after a permission is revoked, the issuer denies further Tickets for it, regardless of the role keys still installed on the authenticator.

### 8.3 Verifier

The verifier MUST validate signature evidence, expected KERI key state, the credential issuer chain, applicable role/relationship semantics, revocation and any anchoring requirement. Missing or stale evidence MUST produce an explicit verification failure, or a limited read-only result where a declared profile defines one.

### 8.4 Enterprise PDP and sessions

The PDP decides effective business permission for each resource. Session issuance and revocation MUST follow authoritative business state; access derived from an AID, ECR/OOR credential or Ticket lasts only as long as the PDP's current decision. Session caching and failure-mode leases belong to an application-layer policy profile such as `VAF-POLICY-1`.

## 9. Security and privacy considerations

### 9.1 Key compromise, physical threats and rollback

The initial profile keeps private keys inside the authenticator interface. Each slot's KEL head advances only through the transitions in Section 3.4, provided persistent storage is intact; complete NVM rollback is outside the initial profile's protection. Deployment risk assessments MUST address interface-level and physical threats separately and define tamper protection and external head reconciliation where required.

### 9.2 Authorization and social engineering

On a displayless authenticator the user's touch confirms presence, and review of the message content takes place off-device. Enterprise approval of message content is therefore a critical control. An attacker who controls the platform and a Ticket-issuer role key, and persuades a legitimate user to touch, can obtain well-formed signatures on unintended content. Product claims about user intent MUST match the controls actually implemented.

### 9.3 Privacy of device and slots

Each `StateProof` contains a persistent device identifier, reset epoch, configuration digest and the state of **all four slots**, which allows correlation across services. Results on the WebAuthn route are also signed with the attestation key, and are returned only to RP IDs listed in `TrustConfig`. Platforms and enterprises MUST limit disclosure of `StateProof`, retain it only as long as necessary, and share slot inventories only with the enrolling enterprise. Selective or pseudonymous state proofs are an open item (Section 13).

### 9.4 Reset, retirement and revocation

Device reset, loss of PIN access, KERI identity retirement, vLEI credential revocation and enterprise session revocation are distinct events. A deployment MUST coordinate all of them; off-device revocation is performed by the enterprise and credential issuers. Pre-rotation private keys remain in raw storage until Reset, and operators MUST evaluate that residual risk.

### 9.5 Attestation trust

Enterprise enrollment MUST authenticate the manufacturer attestation chain out of band, since the runtime `StateProof` carries only the signature. Verifiers MUST use the enrolled attestation public key and a fresh challenge. State attestation is established only by a verified `StateProof` signature.

## 10. VCAP integration and transport independence

### 10.1 Abstract authenticator interface

VAF relies on these VCAP commands: `GetInfo`, `ClientPIN`, `Cancel`, `GetState`, `CreateIdentity`, `PrepareRotation`, `Sign`, `Recover`, `UploadBegin`/`UploadChunk`/`UploadEnd`, `BindEnterprise`, `Personalize` and `Reset`. VCAP assigns their command numbers and specifies exact parameters, error semantics, framing, context isolation and loss-of-response handling. `GetInfo`, `ClientPIN` and `Reset` use the CTAP command codes; the other commands use the CTAP vendor command range.

### 10.2 Transport bindings

A conforming VAF authenticator MUST implement at least one conforming VCAP transport. VCAP 1.0 carries its messages over the CTAP 2.3 transports: CTAPHID over USB and the CTAP NFC binding. The authenticator therefore presents itself to the platform as a FIDO device. VCAP operations are reachable in two ways. Wallets with a native CTAP stack use the CTAP vendor commands. Web pages use the standard WebAuthn API: `navigator.credentials.create()` carries `CreateIdentity`, and `navigator.credentials.get()` carries `Sign`, `GetState`, `PrepareRotation` and `Recover`, marked by a private COSE algorithm identifier and payloads that browsers forward unchanged (VCAP §7.14). Only RP IDs listed in the enterprise-signed `TrustConfig` reach this route; to other sites the authenticator is an ordinary security key. Messages larger than the WebAuthn payload limit (1023 bytes) use the native route. The authenticator also implements the standard CTAP operations and serves as a FIDO2 security key for WebAuthn sign-in; those FIDO credentials are separate from the KERI slots and are not attested with the VCAP attestation key (VCAP §7.13).

### 10.3 Sharing the authenticator with generic FIDO clients

Browsers and operating systems may send `GetInfo`, `ClientPIN` and `Reset` to the authenticator. A VCAP context is exclusive (held) only while its token carries a VCAP permission, a command is executing or an upload is in progress; other channels then receive `CTAP1_ERR_CHANNEL_BUSY`. A context created by a generic client that requests only CTAP permissions never blocks the wallet. A `Reset` sent by a generic client erases all identities on the authenticator; deployments MUST tell users that Reset requires a 5-second hold and what it erases.

## 11. Conformance profiles

### 11.1 VAF-BASE-1 (proposed baseline)

An implementation claiming `VAF-BASE-1` MUST satisfy the following observable capabilities:

| ID | Requirement | Evidence or limit |
| --- | --- | --- |
| VAF-BASE-01 | Authenticator-generated, non-exportable Ed25519 identity keys | `CreateIdentity`, KERI `icp` binding |
| VAF-BASE-02 | Four isolated CLIENT/WORK slots, constrained operations | `GetState`, allowed owner/kind matrix |
| VAF-BASE-03 | One-time enterprise binding and signed TrustConfig | `BindEnterprise`, `Personalize` |
| VAF-BASE-04 | PIN token authorization and fresh per-signature UP | `ClientPIN`, `Sign`, `UploadEnd` |
| VAF-BASE-05 | Challenge-bound signed device state | `GetState` / `StateProof` |
| VAF-BASE-06 | Message- and key-bound enterprise Ticket enforcement | Ticket verification and `KeyRef` |
| VAF-BASE-07 | Single-key, single-head KERI `ICP` / `IXN` / WORK `ROT` | Local KEL checks and atomic state |
| VAF-BASE-08 | Exactly-once local KEL head advancement and latest-event signature recovery | `Recover` for the latest KEL event |
| VAF-BASE-09 | Explicit reset epoch, irreversible reset and failure handling | `Reset`, `RECOVERY_REQUIRED` |
| VAF-BASE-10 | Clear wallet/enterprise archival and network-verification boundary | Integration and negative tests |
| VAF-BASE-11 | At least one conforming VCAP transport binding | CTAPHID over USB or the CTAP NFC binding |
| VAF-BASE-12 | Documented security limits and privacy controls | Threat model and product disclosure |

`VAF-BASE-1` covers single-key personal AIDs. Group operations, delegated events, on-device ACDC verification, anchored presentations, IPEX operation recovery and in-place enterprise root rotation belong to the candidate profiles below.

### 11.2 Candidate extension profiles

- **VAF-IPEX-1** — complete hardware-assisted IPEX Grant/Admit signing and operation-recovery semantics.
- **VAF-GROUP-1** — participating-member keys, threshold/multisig workflow, group AID state and group-specific recovery.
- **VAF-PRES-1** — signed/anchored presentation assurance and privacy-related disclosure requirements.
- **VAF-POLICY-1** — online central PDP decisions and narrowly bounded low-risk cache/failure leases.

A product claims a candidate profile once that profile is specified and the product passes its tests.

## 12. Conformance test intentions

A future public test suite SHALL define machine-readable positive and negative test vectors. The following cases are the required test coverage for that suite:

| Case | Expected outcome |
| --- | --- |
| BASE-T01 | Manufacture, bind, personalize and PIN setup yield the expected lifecycle and reset epoch. |
| BASE-T02 | `CLIENT` and `WORK` ICP bind to the authenticator's current and next keys. |
| BASE-T03 | An event carrying an externally generated `k` or `n` is rejected with `KEY_BINDING`. |
| BASE-T04 | The issuer rejects a `StateProof` with the wrong device, reset epoch or challenge. |
| BASE-T05 | A wrong Ticket digest, role capability, `KeyRef` or signature counter fails and releases no signature; a used Ticket cannot be used again. |
| BASE-T06 | Each successful signature consumes a new touch; a touch already held when the request starts is ignored. |
| BASE-T07 | WORK ROT signs with `old.next`, commits the prepared next key and advances the head exactly once. |
| BASE-T08 | A lost KEL response is resolved by state comparison and the exact `Recover` result. |
| BASE-T09 | A lost EXN response is resolved by the slot's signature counter and `Recover` while no later signature exists, and otherwise only through the Outbox and enterprise archive. |
| BASE-T10 | Physical reset destroys prior-epoch secrets and preserves the enterprise root binding. |
| BASE-T11 | Malformed persistent state leads to `RECOVERY_REQUIRED`. |
| BASE-T12 | The verifier rejects missing credential status, an invalid chain or an unverified anchored claim. |

Transport tests additionally cover CTAPHID channel allocation, multi-frame packet reconstruction, busy-state isolation between held and non-held contexts, keepalive and cancel semantics, NFC command chaining, negative framing tests and cross-transport transaction-recovery tests.

## 13. Open issues and versioning

1. **CLIENT AID rotation:** Should CLIENT keys support rotation while retaining compatibility with the Veridian agent boot sequence? VCAP 1.0 allows rotation for WORK slots only.
2. **Device recovery:** Protected identity keys stay in one authenticator, and the enterprise binding is fixed for its life. KERI continuity and loss recovery require an explicit design.
3. **Group and delegation:** Slots have a single key and threshold `1`, and reject `dip`/`drt`. Group AIDs and delegated events need an extension and test suite.
4. **Signed operation recovery:** The authenticator returns only the most recent non-KEL signature of each slot; IPEX Grant/Admit recovery needs stable operation identifiers and replay/commit evidence.
5. **Attestation privacy:** Every `StateProof` carries all slots and a permanent device identifier. Define minimal proofs and queries in a future version.
6. **Root and roles:** Enterprise root and role keys change only through device replacement or Reset; specify revocation and break-glass procedures.
7. **Signature method:** VCAP 1.0 requires Ed25519 signatures verifiable under RFC 8032 and leaves their computation, including nonce generation, to the implementation. A cryptographic review of each implementation should cover nonce generation, side channels and fault resistance, with test vectors.
8. **KERI version pinning:** BLAKE3 next-key commitments and event templates target the Veridian KERI implementation. A version-negotiation or compatibility-profile registry is needed.
9. **Browser compatibility:** The WebAuthn route (VCAP §7.14) depends on browsers and platform FIDO APIs (Chrome, Edge, Safari and Firefox on Windows, macOS, Android and iOS) forwarding unchanged: the private algorithm identifier, credential IDs of up to 1023 bytes, an `OKP` credential public key with a private label, and an opaque `signature`; and on how each handles silent `up=false` preflight requests. Each needs prototype validation. If platforms filter unknown algorithm identifiers, the fallback marks VCAP requests by the `"VC1"`/`"VQ1"` payload prefixes alone and uses EdDSA (-8) as the algorithm. The value -65700 is provisional.
10. **Formal governance:** Define copyright, license and IPR terms and the change-control process before publication as a stable standard.

Changes to VAF identity/security semantics, VCAP command bytes and CTAPHID transport framing SHALL be tracked separately. Domain separators and codepoints change only through a versioned migration.

## A. Traceability to VCAP 1.0 (informative)

| VAF topic | VCAP 1.0 sections |
| --- | --- |
| Goals and threat model | §§ 1, 4.1, 13.1–13.2 |
| Lifecycle and reset | §§ 4.2, 5, 7.10–7.12, 12.5–12.7 |
| KERI slot and key state | §§ 5.2, 6.3–6.4, 7.5–7.7, 8.4, 8.7 |
| PIN, token and user presence | §§ 5.3, 7.2, 8.1–8.2 |
| Ticket, roles and attestation | §§ 7.4, 8.3, 9.1–9.4, 12.8, Appendix B |
| Recovery and integration | §§ 7.8, 12.2–12.4 |
| WebAuthn route | §§ 7.14, 9.1, 12.9 |
| Status codes | § 10 |
| Transport | § 11 (11.1 message encoding, 11.2 CTAPHID, 11.3 NFC) |
| Group, delegation and IPEX boundaries | §§ 5.2, 8.4.2, 8.5, 12.3 |

## B. References

### B.1 Normative references (subject to profile pinning)

- [BCP14] RFC 2119 and RFC 8174 — <https://www.rfc-editor.org/info/bcp14/>
- [KERI] ToIP KERI working specification — <https://github.com/trustoverip/kswg-keri-specification>
- [CESR] ToIP CESR working specification — <https://github.com/trustoverip/kswg-cesr-specification>
- [ACDC] ToIP ACDC working specification — <https://github.com/trustoverip/kswg-acdc-specification>
- [vLEI-EGF] GLEIF vLEI Ecosystem Governance Framework — <https://www.gleif.org/en/organizational-identity/become-a-vlei-issuer-qvi/vlei-ecosystem-governance-framework>
- [VCAP] [VCAP 1.0](https://vlei-auth.github.io/vcap/) — published from the review draft *vLEI Key Authenticator Protocol 1.0*.
- [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — <https://www.rfc-editor.org/rfc/rfc8032>
- [CTAP] FIDO Alliance, *Client to Authenticator Protocol v2.3* — <https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html>
- [WEBAUTHN] W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3* — <https://www.w3.org/TR/webauthn-3/>
