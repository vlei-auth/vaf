# vLEI Authenticator Framework (VAF) — Version 1.0

*Editor's Draft — 7 November 2026*

**Specification identifier:** VAF-1.0  
**Editor's Draft URL:** https://vlei-auth.github.io/vaf/  
**Short name:** VAF  
**Status:** Editor's Draft  
**Editors:**
  * Fan Dang (ACentauri Technology Limited)

**Companion protocol:** [VCAP 1.0 — vLEI Client to Authenticator Protocol](https://vlei-auth.github.io/vcap/)  
**Companion interface:** [VCAP-EI 1.0 — VCAP Enterprise Interface](https://vlei-auth.github.io/vcap-ei/)

## Abstract

This specification defines an interoperable hardware-backed authenticator model for KERI-based identifiers used in vLEI applications. VAF specifies the participants and trust boundaries, minimum authenticator security guarantees, supported KERI operations, enterprise authorization semantics, attestation and state evidence, lifecycle and loss-recovery obligations, and conformance profiles. The companion protocol **VCAP 1.0** defines authenticator commands, exact encodings, responses and transports.

## Status of this document

This is an unpublished **Editor's Draft** for public review. It describes a concrete initial security architecture. Independent security review, interoperability testing, governance review and standardization are pending; the requirements below, stated with the keywords of Section 1.3, are proposed conformance requirements for that review. Copyright, license and intellectual-property terms, and the change-control process, are defined before publication as a stable standard.

## 1. Introduction

### 1.1 Design goals

An employee receives an enterprise-issued physical key and uses it over USB or NFC, from a wallet or from an enterprise web page through the browser's WebAuthn API, to operate KERI identities and interact with vLEI business applications, while the identity-control private keys stay inside the authenticator. Any KERI client that implements VCAP and obtains enterprise Tickets can use the same authenticator.

A conforming deployment SHOULD keep the following responsibilities separate: the authenticator proves possession of protected KERI keys and enforces local signing restrictions; the enterprise authorizes each signing operation through a Ticket; the KERI infrastructure determines network-accepted key state; an ACDC/vLEI verifier determines credential validity; and the relying party's policy decision point (PDP) makes the final business authorization decision.

### 1.2 Scope

VAF specifies (a) roles and architectural boundaries; (b) authenticator-level identity and signing properties; (c) device state and evidence semantics; (d) enterprise policy binding; (e) platform, issuer and verifier responsibilities; (f) security and privacy guarantees and their limits; and (g) conformance requirements.

VCAP specifies command values, parameters, error semantics, framing and transport bindings. KERI event serialization, CESR encoding, ACDC schemas, IPEX messages, witness infrastructure and OIDC session tokens are governed by their respective specifications.

Participation of a slot in group (multi-signature) AIDs is specified by the profile `VAF-GROUP-1` (Section 11.4), which builds on the optional group member signing feature of VCAP. VAF 1.0 does not cover: delegated inception and rotation (`dip`, `drt`), including delegated group AIDs; rotation of CLIENT AIDs; continuation of an AID on another authenticator (Section 6.5); KERI versions and serializations other than KERI 1.0 JSON with the syntax of VCAP §8.4.3; selective or pseudonymous state proofs; and recovery of operations that span several non-KEL messages, such as IPEX grant and admit. Section 11.3 lists candidate extension profiles for some of these.

### 1.3 Conformance terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED** and **MAY** in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here. Each normative requirement applies to the conformance class it names (Section 11.1) and to the declared profile. Examples, explanatory notes and candidate profiles are informative unless explicitly marked otherwise.

### 1.4 Relationship to existing standards

VAF builds on the following external systems and uses their definitions as published:

| System | Authority | VAF integration boundary |
| --- | --- | --- |
| **KERI** | [KERI], restricted to the event syntax of VCAP §8.4.3 | AIDs, key events, current/next keys, commitments, sequence numbers, prior event links |
| **CESR / SAID** | [CESR] | External signature attachments and content-addressed identifiers |
| **ACDC / IPEX** | [ACDC] | Credentials, disclosure and exchange handled by wallet/agent/verifier |
| **vLEI** | GLEIF vLEI Ecosystem Governance Framework (EGF) | Credential types, issuance, revocation, legal/role trust chain |
| **VCAP** | Companion device protocol | Exact command values, wire structures, transport, PIN and state encodings |
| **VCAP-EI** | Companion enterprise interface | Ticket requests, archiving, recovery, message submission and Agent relay between platform and enterprise service |
| **CTAP 2.3 / WebAuthn** | FIDO Alliance, W3C | Transports (CTAPHID, NFC, and the NFC APDU layer over USB CCID), PIN protocol, generic-client sharing and the optional WebAuthn route of VCAP |

VAF conformance is a claim about this specification only. GLEIF qualification and FIDO certification are separate programs with their own requirements.

## 2. Actors and trust boundaries

### 2.1 Actors

- **Authenticator:** an external hardware unit holding its attestation identity and exactly four independently stateful key slots in the initial profile.
- **Platform:** an untrusted client of the authenticator, responsible for preparing the actual message, maintaining an Outbox and contacting external services.
- **Manufacturer:** provisions the device attestation identity and issues its leaf certificate.
- **Enterprise administrator:** verifies manufactured device identity, binds the tenant and enterprise root, and provisions the enterprise-signed `TrustConfig`.
- **Ticket issuer:** validates device state and the requested action, persists the message, and signs a single-use Ticket that authorizes one digest-bound cryptographic operation.
- **KERI agent / infrastructure:** validates and publishes key events, collects witness receipts and tracks network state; may provide Signify/KERIA-compatible application functionality.
- **Credential verifier:** validates the ACDC/vLEI issuance chain, holder proof, disclosure, status and required anchoring.
- **Relying party / PDP:** applies current business roles, resource policy, revocation, session state and risk constraints.

In this document, **Enterprise Service** denotes the enterprise administrator, Ticket issuer, archive and the KERI services the enterprise operates, taken together, as in the conformance class of Section 11.1; a requirement on the Ticket issuer applies to the Enterprise Service that operates it. **Platform** includes wallets and enterprise web pages (VCAP §3.1).

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

Status reporting MUST distinguish the stages **device signed**, **enterprise archived**, **network accepted**, **credential verified** and **business authorized**. Under `VAF-GROUP-1`, a group event or message also passes the stage **threshold met** (member signatures meeting the group's thresholds collected) before it is network accepted or delivered.

## 3. Authenticator and identity model

### 3.1 Device binding

Each authenticator MUST have a protected device attestation identity. The initial profile uses an Ed25519 attestation key pair with a leaf certificate issued by the manufacturer; how the manufacturer provisions them is outside VAF. The device presents the certificate itself while it is not in `PIN_READY` (binding-mode `GetState`, VCAP §7.4.3), so enrollment needs only the manufacturer's CA certificates, with its root as trust anchor, and no per-device file from the manufacturer. The enterprise MUST verify the chain and bind the attestation public key to its enrollment record before accepting state evidence, and thereafter verifies each `StateProof` with that enrolled public key.

The initial profile MUST implement an enterprise binding. `BindEnterprise` fixes a `tenant` and `enterpriseRoot` for the physical device until the next reset, and a reset MUST remove that binding. Reusing a device, for the same or another enterprise, requires a reset and a new `BindEnterprise`.

### 3.2 Slots and owner classes

VCAP 1.0 defines exactly four slots (`0..3`), each with owner `CLIENT=1` or `WORK=2` and phase `UNUSED`, `CREATED` or `ACTIVE`. Any mix of owners is permitted, including four WORK slots. Once assigned, a slot keeps its identity until the next reset epoch. Owner names denote **cryptographic operation profiles**; a natural person's legal identity is established by validated vLEI credentials bound to the AID (Section 7.2).

| Owner | Purpose | Allowed operation kinds |
| --- | --- | --- |
| `CLIENT` | Client AID that controls the employee's KERI agent | `ICP`, `IXN` |
| `WORK` | Work AID used for vLEI credentials and exchanges | `ICP`, `IXN`, `ROT`, `EXN`, `RPY`; with `VAF-GROUP-1` also `GROUP`, `GROUP_SUPERSEDE` and `GROUP_EXN` |

Each slot holds one single-key, non-delegated KERI AID whose keys are all generated inside the authenticator. The initial profile advertises exactly the operations in the table above. A WORK slot can in addition be a member of group AIDs under `VAF-GROUP-1` (Section 3.6); the group AID is not held in the slot. Delegated inception and rotation, and CLIENT rotation, are outside VAF 1.0 (Section 1.2).

The agent that a CLIENT AID controls is identified by an agent profile. VAF 1.0 places no requirement on the agent implementation; VCAP-EI 1.0 defines the KERIA agent profile, under which the enterprise creates a KERIA agent from the CLIENT inception and relays the platform's Agent requests under the employee's enterprise bearer token. Reading from or updating the Agent does not use the authenticator; only signatures by slot keys do.

### 3.3 Key ownership and commitments

The authenticator MUST generate current and next private signing keys inside its trust boundary; VCAP provides no command that imports, exports or accepts an external private key. On KERI inception, the authenticator checks that the event's current key and next-key commitment match its own generated keys. Before a rotation, `PrepareRotation` generates the new next key inside the device. On rotation, the authenticator signs with the previously committed `old.next` private key and checks that the event commits to the prepared new next key. Every key and commitment in a signed event is therefore an authenticator-generated key.

The initial profile constrains a slot's own `icp` and `rot` to one current key (`kt="1"`), one next-key commitment (`nt="1"`), and BLAKE3-256 next-key digests. This is a subset of KERI. In a group `icp` or `rot` that a slot signs as a member (Section 3.6), the authenticator checks that its own current key and its own next-key commitment each appear exactly once in `k` and `n`; the other members' keys come from their own authenticators or key stores and are checked by the Enterprise Service.

### 3.4 KERI event head and fork prevention

Each ACTIVE slot MUST keep a durable head describing its most recently committed event. An `ICP` MUST have `s=0` and `d=i`; an `IXN` or `ROT` MUST have sequence `latest.seq + 1`, `p` equal to `latest.said`, and `i` equal to the slot AID. The authenticator MUST update the slot head atomically before returning the signature of a KEL event. As a result, the authenticator's interface advances each slot's KEL strictly one event at a time and never produces two events with the same sequence number, given intact persistent storage. Network acceptance of each event is established separately by the KERI infrastructure (Section 6.4).

### 3.5 Employee AIDs and legal-entity AIDs

AIDs held in the authenticator's slots belong to the employee. They are distinct from the legal entity's AID and from any group AID in which the employee participates. Authority over the legal entity's AID is defined by that AID's own key state and by the vLEI EGF; an employee's WORK AID and any role credential issued to it convey exactly the authority stated in that credential.

### 3.6 Group AIDs (`VAF-GROUP-1`)

A group AID, such as a legal entity's AID controlled by several authorized representatives, lists in `k` and `n` the keys and next-key commitments of its members and is controlled through the thresholds `kt` and `nt`. Under `VAF-GROUP-1`, an ACTIVE WORK slot takes part as a member: it signs the group's `icp`, `ixn` and `rot` with its current key under kind `GROUP`, the group's `exn` messages (for example an IPEX `grant` of a credential the group issues) under kind `GROUP_EXN`, and the group's `rpy` messages (for example an end-role reply for the group) under kind `RPY`, and sends each signature to the other members in a `/multisig/*` `exn` signed under kind `EXN` (VCAP §12.10). The group's KEL is not held by the authenticator; each member slot keeps one **group record** per group AID it has signed for, holding the sequence number, SAID and signature of its latest signed event of that group (VCAP §5.2).

Preventing a fork of a group KEL is shared between three parties:

1. **Authenticator.** For each (slot, group AID) it signs at most one event per sequence number, only at increasing sequence numbers, and, when the next sequence number follows directly, only an event whose `p` is the SAID it signed before (VCAP §8.4.4). Without the `GROUP_SUPERSEDE` capability this holds even if the platform and the Enterprise Service are compromised. `GROUP_SUPERSEDE` signs one replacement event at the record's own sequence number and with the same prior event, at most once per sequence number, needs its own capability bit and is recorded in the group record; it can also reuse the record of an abandoned group inception. A slot holds at most `GROUP_RECORDS` (VCAP Appendix A: two) group records, stored and committed with the slot's own state.
2. **Enterprise Service.** It approves only events that extend the group's network-accepted key state, at most one original per (group AID, sequence number) across all members it serves, and issues `GROUP_SUPERSEDE` Tickets only for a proposal it has determined, on the grounds of VCAP §12.8 item 7.5, cannot reach its threshold, under a separately controlled role key (VCAP §12.8 item 7). It also verifies what the authenticator cannot: membership in the current key state, thresholds, prior next-key commitments and witnesses.
3. **KERI.** A competing event needs signatures meeting the group's threshold, and witnesses and watchers detect duplicity among accepted events.

The platform builds the group event and coordinates with the other members, but it is untrusted (Section 2.2): it can delay or withhold a member signature, not produce one. A platform SHOULD compare a group event with the group's key state and show the group AID, event type and sequence number to the user before requesting the Ticket; this aids the user and does not replace the checks above.

A member's share in a group is its slot's current key and next-key commitment, the same ones its own AID uses, so the slot's own rotation (`ROT`) changes its share in every group it belongs to. The Enterprise Service coordinates a member's own rotations with the rotations of its groups (VCAP §12.8 item 7.7, §12.10).

Members of a group may hold their keys on different authenticators, enterprises or key stores; the authenticator's guarantee covers only its own slots. In VAF 1.0 every member key of a group in which a slot takes part is an Ed25519 key and every next-key commitment a BLAKE3-256 digest (VCAP §8.4.4); the Enterprise Service checks this also for events whose keys the authenticator does not see. A group whose members all depend on the same Enterprise Service relies on that service for item 2; the authenticator's item 1 still holds without it.

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
Any state except RECOVERY_REQUIRED + Reset
  (within 10 s of power-on, 5-second hold)      → STOCK_UNBOUND, resetEpoch + 1
Valid reset intent record found at start-up     → STOCK_UNBOUND, resetEpoch + 1
Unrecognized or corrupted persistent data       → RECOVERY_REQUIRED
RECOVERY_REQUIRED + Reset (attestation identity → STOCK_UNBOUND, resetEpoch + 1
  and reset epoch readable)
```

The authenticator MUST treat missing or corrupted data in previously initialized storage as `RECOVERY_REQUIRED` and preserve that data until a Reset. In `RECOVERY_REQUIRED`, the authenticator accepts only `GetInfo`, status-mode `GetState`, `Cancel` and `Reset`. Reset destroys the unreadable data, removes the enterprise binding and starts a new reset epoch; if the attestation identity or the reset epoch is unreadable, the device requires offline maintenance.

### 4.2 Personalization and enterprise governance

The authenticator MUST verify `TrustConfig` against the bound enterprise root, the device identifier, tenant and current reset epoch. `TrustConfig` contains an owner mask, a minimum PIN length, 1–8 role public keys with their capability masks, and the SHA-256 digests of the enterprise RP IDs allowed to use the WebAuthn route (VCAP §7.14). An enterprise that uses only WORK identities sets an owner mask without CLIENT. Personalization happens once per reset epoch and is performed by the enterprise with the device under its control. The PIN SHOULD be set by the employee on their own platform, so the enterprise hands the device over in `PERSONALIZED_NO_PIN` and never learns the PIN (VCAP §12.5). After a Reset, personalization for the new epoch is again performed by the enterprise. Changing role keys or enterprise policy requires a Reset followed by a new Personalize. An Enterprise Service MUST document the resulting emergency-revocation and service-availability procedures.

### 4.3 PIN and UP

The device MUST enforce its own PIN retry limits with durable failed-attempt accounting, and MUST receive the PIN encrypted under CTAP `pinUvAuthProtocol 2` (P-256 ECDH, HKDF-SHA-256, AES-256-CBC, HMAC-SHA-256), which VCAP `ClientPIN` uses unchanged. VCAP 1.0 uses the CTAP PIN retry and power-cycle lockout rules, and adds `READ`, `SIGN` and `MANAGE` token permissions above the CTAP permission bits. PIN-derived material and tokens MUST be discarded when the context ends. Every signature by a slot key (`Sign`, `UploadEnd`, or a signature requested through WebAuthn) MUST consume its own new user action, either a sensor press or, over NFC, the tap into the reader's field (one tap per field session); over USB HID and USB CCID the action is always a sensor press. `BindEnterprise` and `Personalize` also require a touch, and `Reset` requires a 5-second hold. The authenticator MUST have a touch sensor and a presence indicator light (VCAP §8.2).

A platform MUST present a touch to the user as confirmation of presence and MUST NOT present it as approval of message content. Assurance for message content comes from content confirmation outside the authenticator and from the Ticket issuer's approval (Section 9.2).

### 4.4 Reset and retirement

A physical reset MUST make the PIN record, all slot private keys (including pre-rotation historical keys) and all FIDO credentials unrecoverable, increment `resetEpoch`, remove the enterprise binding and personalized state, and retain the attestation identity and `resetEpoch`. `resetEpoch` never decreases, including across a later `BindEnterprise`, so configuration and Tickets of an earlier epoch never become valid again. The reset intent MUST survive power interruption, so that a reset interrupted after its intent record is written completes at the next start. Reset acts only on the device: the Enterprise Service MUST separately invalidate earlier Tickets, user roles, active sessions and network identities per Section 6.5.

## 5. Enterprise authorization model

### 5.1 Separate cryptographic, credential and business authorization

Every signature by a slot key requires a valid Ticket. A Ticket authorizes one **specific cryptographic operation**; vLEI credentials, OIDC sessions and application permissions are separate authorization layers. A verified OOR/ECR credential with current status and a valid chain may contribute an attribute to a PDP decision.

### 5.2 TrustConfig and role capabilities

The role public keys, role identifiers and capability masks MUST be bound by a `TrustConfig` signature under the enterprise root. Each capability bit names one (owner, kind) pair. A conforming Ticket issuer MUST sign only operations whose (owner, kind) pair is in the signing role's capability mask, and the authenticator MUST independently check the capability mask for each request.

### 5.3 Ticket semantics

In VCAP 1.0, a Ticket is an enterprise role-key signature, under domain tag `VCAP-SIGN\0`, over:

```text
[version, kind, signerKeyRef, signCounter,
 originalDigest, originalLength]
```

The authenticator derives `KeyRef` from its own verified slot state: device identity, reset epoch, slot, owner and the **actual** signing public key (`old.next` for `ROT`, `current` otherwise), and compares it with `signerKeyRef`. The digest binds the Ticket to exact bytes. `signCounter` is the value the slot's persistent signature counter will take with this signature; the authenticator accepts the Ticket only when the counter currently equals `signCounter − 1`, and advances it in the same atomic commit as the signature. Each Ticket is therefore usable once, independent of any transport session, and can be obtained before the authenticator is connected.

The Ticket issuer MUST base each Ticket on reliable state evidence: a fresh `StateProof` bound to its own single-use challenge, or an archived original signature together with network-accepted head progression. It MUST persist the requested message before signing the Ticket, and check its semantics and risk. When it issues a replacement Ticket for a counter value whose earlier Ticket went unused, it treats the earlier Ticket as still usable until the counter advances. The issuer learns the counter from archived signatures, a `StateProof`, or the `signCount` of a WebAuthn response.

**Replay and time boundary:** every Ticket becomes unusable once any signature on its slot commits. A Ticket carries no time limit: an unused Ticket stays valid until the next signature on the slot, and the enterprise revokes it by having another signature made or by Reset. Timeliness comes from issuance-time checks and from the messages themselves (the KEL head binding and `dt` in `exn`/`rpy`). Recipients SHOULD still enforce request-level anti-replay as defense in depth.

**Content checks and enterprise discretion:** A Ticket decision serves two functions. Its **content checks** (format, state, consistency with the AID's currently valid credentials, and, under `VAF-GROUP-1`, the group rules) are the control against induced signing on a displayless authenticator (Section 9.2); the issuer SHOULD perform them automatically from verifiable state. Any further restriction the enterprise applies to the employee's acts (for example permitted counterparties) is **enterprise discretion**: an internal control of the legal entity. Neither is visible to a verifier, and a signature does not show that an enterprise approved it. Authority to act for the legal entity is expressed by the vLEI credentials and their revocation (Section 7); a Ticket decision does not grant or withdraw it. Risk classes, rule sets and their audit are the subject of `VAF-POLICY-1` (Section 11.3).

### 5.4 Operation categories

The baseline capability registry consists of the five VCAP signing kinds (`ICP`, `IXN`, `ROT`, `EXN`, `RPY`) combined with the owners listed in Section 3.2 (seven valid combinations, VCAP Appendix B). `VAF-GROUP-1` adds three combinations, WORK `GROUP`, WORK `GROUP_SUPERSEDE` and WORK `GROUP_EXN`. VAF defines their authorization purpose; VCAP defines the numeric values and exact validation algorithm. Agent requests that produce no slot signature (reads, contact and notification metadata) are authorized by the enterprise PDP from the employee's bearer token and are not Ticket operations (VCAP-EI §7.11, Appendix C).

## 6. Signing and recovery

### 6.1 Signing protocol boundary

The authenticator receives the complete message bytes, computes their digest itself and checks it against the Ticket's digest and length, verifies KERI field and key consistency for the operation kind, and collects a fresh UP before releasing a signature. The platform MUST independently verify the returned signature over its own saved message bytes.

For KEL events, the authenticator checks the version-string size, event type, `i`, `s`, `p`, `d` format, current keys, thresholds and next-key commitment. The Enterprise Service MUST verify the SAID, witness receipts, delegation and network acceptance before treating the event as valid in the wider ecosystem.

### 6.2 Atomic KEL commit and response loss

For `ICP`, `IXN` and `ROT`, the device MUST atomically persist its new head (and rotated keys for `ROT`) before releasing the result. It MUST store the original signature of the latest event, and of the most recent signature of any kind, and return **that exact signature** through `Recover` when given the matching message digest.

When a response to `Sign`, `UploadEnd`, `CreateIdentity` or `PrepareRotation` is lost, the platform MUST open a new context, obtain a new challenge-bound `StateProof`, and compare the slot state with the expected result. For a committed KEL event it then calls `Recover` or retrieves archival evidence; if the head is unchanged, the enterprise decides whether to issue a new Ticket.

### 6.3 Non-KEL recovery

Every signature, including `EXN` and `RPY`, advances the slot's signature counter, so a `StateProof` shows whether a Ticket was used. The authenticator keeps the most recent signature of each slot; while no later signature has been made, a lost non-KEL response is retrieved with `Recover`. Older non-KEL signatures come only from the platform Outbox and the enterprise archive. Recovery of operations that span several messages is outside VAF 1.0 (Section 1.2).

Under `VAF-GROUP-1`, a member signature on a group event advances the slot's signature counter and replaces the slot's group record for that group AID. A `StateProof` requested with the group AID reports the record, and `Recover` returns its signature until a later event of the same group AID replaces it, also after later signatures of other kinds. Older member signatures come from the platform Outbox and the enterprise archive (VCAP §12.3). A `GROUP_EXN` signature does not change the group record and is recovered as an `EXN`.

### 6.4 KERI network acceptance

A local commit is reported as **device signed**; witness receipts, completed delegation, KEL acceptance and business settlement are reported only from their own evidence. When an authoritative party permanently rejects a committed event and the Enterprise Service accepts that rejection, it marks the slot as rejected and issues no further Tickets for it in the current reset epoch; the slot's head stays as committed, and reusing the slot requires a Reset. After a temporary failure, the enterprise redelivers the original signature.

### 6.5 Device loss, Reset and identity continuity

Every identity-control key of a slot exists only inside one authenticator, and a rotation commits only to keys generated inside the same authenticator (Section 3.3). An AID held in a slot therefore continues only on that authenticator. Loss, theft or destruction of the device, a Reset, and a blocked PIN (which leads to a Reset) each end the continuity of every AID on the device. The following requirements apply when any of these events is reported or decided.

The Enterprise Service:

1. MUST mark the device, or the affected reset epoch, as retired in its enrollment record before it issues any further Ticket for the device, and from then on MUST refuse Tickets for every slot it covers and MUST NOT deliver Tickets already issued for them.
2. MUST revoke the sessions derived from the affected AIDs, and deactivate the agents controlled by the affected CLIENT AIDs.
3. MUST record each affected AID as retired and report it as inactive through VCAP-EI `aid-status`.
4. MUST request the issuers of vLEI credentials whose issuee is an affected WORK AID to revoke those credentials, following the vLEI EGF, and MUST record the request.
5. MUST reuse a recovered device only after a Reset, a new `BindEnterprise` and a new `Personalize`.
6. MAY onboard a replacement device per VCAP §12.5, which creates new AIDs. Credentials for the employee are issued anew to the new WORK AIDs; any link between old and new AIDs is established by the enterprise's records and by the newly issued credentials.
7. Under `VAF-GROUP-1`, MUST stop issuing Tickets for group events and messages on behalf of the affected WORK AIDs, MUST inform the other members of each group AID in which an affected WORK AID is a member, through the group's agreed coordination channel or out of band, and MUST record that notification, so that they can rotate the lost member key out of the group and, if the employee remains a member, a new WORK AID of the employee in.

A Platform that learns that an AID is inactive MUST stop requesting Tickets and signatures for it.

A Verifier MUST evaluate a presentation by an affected AID according to the current status of its credentials (Section 8.3).

An unused Ticket issued before the event remains acceptable to the authenticator until the slot's next signature (Section 5.3). Step 1 keeps such Tickets from being delivered, and recipients reject messages whose own validity (`dt`) has passed.

## 7. vLEI credential interaction and presentation

### 7.1 Storage and validation boundary

The initial VAF profile protects KERI signing keys inside the authenticator. Full ACDC objects, KELs, OOR/ECR credentials, status registries and IPEX message state are held by the wallet, agent and verifier, which manage credential discovery, disclosure selection, proof-chain checking, issuance trust, revocation status and external anchoring.

### 7.2 Credential-holder proof

When ACDC/IPEX semantics allow, a presentation for a credential issued to a WORK AID MAY use an authorized device signature as holder evidence. The verifier MUST validate the purpose, verifier challenge, issuee binding, signature, the AID's KERI key state, credential status and disclosure requirements. A device signature proves control of the AID; a valid vLEI role is established by the verified credential chain.

### 7.3 IPEX integration

A WORK slot signs any `exn` message whose `i` equals the slot AID, so an off-device agent can build and exchange IPEX messages (for example `grant` and `admit`) signed by the authenticator. The enterprise validates the route, recipient and business meaning before issuing the Ticket. End-to-end IPEX conformance, replay-safe operation recovery and presentation-policy enforcement are outside VAF 1.0 (Section 11.3).

## 8. Platform, verifier and PDP obligations

### 8.1 Platform

Platforms MUST submit a `StateProof` with the Ticket request whenever their knowledge of the slot head or counter is uncertain; write the message to the Outbox after receiving the Ticket and before sending `Sign`; verify the returned signature and signer key; recover lost responses through state comparison (Section 6.2); report transport success and application success separately; and clear PIN, shared secrets and tokens when the session ends. On the WebAuthn route the browser handles the PIN and token, and the message stored by the enterprise before Ticket issuance serves as the Outbox. After a transport reconnection the platform establishes a new context and token, and determines the outcome of any in-flight operation through `GetState`.

### 8.2 Ticket issuer

A Ticket issuer MUST verify enrollment, attestation public key, tenant, reset epoch, authoritative current state, role authorization, request content, message format and risk before signing a Ticket. Its state evidence is either a `StateProof` answering a single-use challenge it generated, or its archived head and signature counter (an archived original signature, or network-accepted head progression). It MUST persist an audit record and the original message before signing. Ticket issuance follows the enterprise's current permission state: after a permission is revoked, the issuer denies further Tickets for it, regardless of the role keys still installed on the authenticator. When the issuer denies Tickets for an AID because its holder no longer holds a role, the Enterprise Service MUST also request revocation of the affected vLEI credentials from their issuers, following the vLEI EGF, and MUST record the request; withholding Tickets does not withdraw the role.

For `GROUP`, `GROUP_SUPERSEDE` and `GROUP_EXN` Tickets, and for `RPY` Tickets of a group AID, the issuer additionally follows VCAP §12.8 item 7: its state basis is the group's network-accepted key state together with the slot's group record; it approves at most one original per (group AID, sequence number) across all members it serves; and it signs `GROUP_SUPERSEDE` only under a role key reserved for that capability, after recording a determination on the grounds of VCAP §12.8 item 7.5. Before a WORK `ROT` Ticket for a slot that holds group records, it checks the effect on each group (VCAP §12.8 item 7.7).

Before issuing a Ticket for an IPEX admit of a credential that the enterprise will treat as a vLEI credential, the Ticket issuer MUST verify, as the verifier of Section 8.3, that: the credential's issuer chain ends at the GLEIF Root of Trust whose AID the enterprise has configured out of band; each credential in the chain has the schema and the edges that the vLEI EGF requires for its type (QVI, legal entity, OOR authorization, OOR, ECR authorization, ECR); the issuee is the slot's AID; and no credential in the chain is revoked, according to status read from its registry for this decision rather than from a cache. A credential that fails these checks MAY be admitted under an explicit enterprise policy, but MUST NOT then be treated or displayed as a vLEI credential.

### 8.3 Verifier

The verifier MUST validate signature evidence, expected KERI key state, the credential issuer chain, applicable role/relationship semantics, revocation and any anchoring requirement. Missing or stale evidence MUST produce an explicit verification failure, or a limited read-only result where a declared profile defines one.

### 8.4 Enterprise PDP and sessions

The PDP decides effective business permission for each resource. Signing and reading have separate requirements: a slot signature needs the authenticator, a Ticket and a fresh UP, while reading needs only an authenticated employee session that the PDP currently allows; a platform MUST NOT require the authenticator for read-only access. Session issuance and revocation MUST follow authoritative business state; access derived from an AID, ECR/OOR credential or Ticket lasts only as long as the PDP's current decision. Session caching and failure-mode leases belong to an application-layer policy profile such as `VAF-POLICY-1`.

## 9. Security and privacy considerations

### 9.1 Key compromise, physical threats and rollback

The initial profile keeps private keys inside the authenticator interface. Each slot's KEL head advances only through the transitions in Section 3.4, provided persistent storage is intact; complete NVM rollback is outside the initial profile's protection. An Enterprise Service's risk assessment MUST address interface-level and physical threats separately and define tamper protection and external head reconciliation where required.

### 9.2 Authorization and social engineering

On a displayless authenticator the user's touch confirms presence, and review of the message content takes place off-device. Enterprise approval of message content is therefore a critical control. An attacker who controls the platform and a Ticket-issuer role key, and persuades a legitimate user to touch, can obtain well-formed signatures on unintended content. Authenticator product documentation MUST state that a touch establishes user presence and that content review takes place off-device.

`CreateIdentity` requires a PIN token but no Ticket. A platform that holds the PIN can therefore occupy UNUSED slots until the next Reset; such a slot cannot sign without a Ticket. The Enterprise Service detects unexpected slots from `StateProof` (VCAP §13.2).

### 9.3 Privacy of device and slots

Each `StateProof` contains a persistent device identifier, reset epoch, configuration digest and the state of **all four slots**, which allows correlation across services. Results on the WebAuthn route are also signed with the attestation key, and are returned only to RP IDs listed in `TrustConfig`. A `StateProof` requested with a group AID also shows that the employee's slot is a member of that group. Platforms and enterprises MUST limit disclosure of `StateProof`, retain it only as long as necessary, and share slot inventories only with the enrolling enterprise. VAF 1.0 defines no selective or pseudonymous state proofs.

Before a PIN is set, the device also answers an unauthenticated request with a signed `BindingProof` (VCAP §7.4.3) carrying its device identifier, its enterprise binding and reset epoch (none after a Reset), and on request its attestation certificate chain. This lets the enterprise learn whether the device is still in the binding it recorded and which reset epoch it is in, including after a Reset it did not order. The same proof identifies the device and its enterprise to any host it is connected to while it is not in PIN_READY; the same disclosure limits apply.

### 9.4 Reset, retirement and revocation

Device reset, loss of PIN access, KERI identity retirement, vLEI credential revocation and enterprise session revocation are distinct events. The Enterprise Service MUST coordinate them per Section 6.5; off-device revocation is performed by the enterprise and credential issuers. Pre-rotation private keys remain in raw storage until Reset, and operators MUST evaluate that residual risk.

The enterprise root key is fixed on a device by `BindEnterprise` and the role keys by `Personalize`; within a reset epoch they change only through Reset or device replacement. Compromise of the enterprise root key, or of a role key that cannot be withdrawn otherwise, therefore requires Reset or replacement of every affected device. The Enterprise Service MUST protect these keys accordingly and MUST stop issuing Tickets under a compromised key.

### 9.5 Attestation trust

Enterprise enrollment MUST verify the attestation chain against the manufacturer's root and issuing CA certificates obtained out of band (VCAP Appendix D.2); the chain itself MAY come from the device (VCAP §7.4.3), since it is authenticated by that root. The runtime `StateProof` carries only the signature. Verifiers MUST use the enrolled attestation public key and a fresh challenge. State attestation is established only by a verified `StateProof` signature.

## 10. VCAP integration and transport independence

### 10.1 Abstract authenticator interface

VAF relies on these VCAP commands: `GetInfo`, `ClientPIN`, `Cancel`, `GetState`, `CreateIdentity`, `PrepareRotation`, `Sign`, `Recover`, `UploadBegin`/`UploadChunk`/`UploadEnd`, `BindEnterprise`, `Personalize` and `Reset`. VCAP assigns their command numbers and specifies exact parameters, error semantics, framing, context isolation and loss-of-response handling. `GetInfo`, `ClientPIN` and `Reset` use the CTAP command codes; the other commands use the CTAP vendor command range.

### 10.2 Transport bindings

A conforming VAF authenticator MUST implement at least one VCAP transport: CTAPHID over USB HID, the CTAP NFC binding, or USB CCID, which carries the APDUs of the CTAP NFC binding over a contact smart-card interface reachable through the operating system's smart-card service (VCAP §11.4). The authenticator presents itself to the platform as a FIDO device and lists its transports and `"VCAP_1_0"` in GetInfo.

An authenticator MAY in addition implement the WebAuthn route (VCAP §7.14), through which web pages use the standard WebAuthn API: `navigator.credentials.create()` carries `CreateIdentity`, and `navigator.credentials.get()` carries `Sign`, `GetState`, `PrepareRotation` and `Recover`, marked by a private COSE algorithm identifier and payloads that browsers forward unchanged. Only RP IDs listed in the enterprise-signed `TrustConfig` reach this route; to other sites the authenticator is an ordinary security key. A request on this route is limited to 1023 bytes including the Ticket, so larger messages use the native route. Browsers do not keep the PIN token between calls, so each call takes one PIN entry and one user action; the enterprise therefore issues Tickets from its archived state, so a signature takes one call, and resolves an unknown outcome with one read-only call (VCAP §12.9). The authenticator also implements the standard CTAP operations and serves as a FIDO2 security key for WebAuthn sign-in; those FIDO credentials are separate from the KERI slots and are not attested with the VCAP attestation key (VCAP §7.13).

### 10.3 Sharing the authenticator with generic FIDO clients

Browsers and operating systems may send `GetInfo`, `ClientPIN` and `Reset` to the authenticator. A VCAP context is exclusive (held) only while its token carries a VCAP permission, a command is executing or an upload is in progress; other channels then receive `CTAP1_ERR_CHANNEL_BUSY`. A context created by a generic client that requests only CTAP permissions never blocks the wallet. A `Reset` sent by a generic client erases all identities on the authenticator; deployments MUST tell users that Reset requires a 5-second hold and what it erases.

## 11. Conformance

### 11.1 Conformance classes

| Class | Who | Requirements |
| --- | --- | --- |
| **Authenticator** | Producer of authenticator hardware and firmware | Sections 3, 4, 6.1–6.2, 9.1, 10; VCAP class Authenticator (VCAP §2.1) |
| **Manufacturer** | Party that provisions the attestation identity and issues its leaf certificate | Section 3.1; VCAP Appendix D.1, D.5 |
| **Platform** | Wallet or enterprise web page that uses the authenticator | Sections 6.2–6.5, 8.1, 8.4; VCAP classes Platform and Web platform; VCAP-EI class Platform |
| **Enterprise Service** | Ticket issuer, archive and enrollment service of the enterprise | Sections 4.2, 5, 6.2–6.5, 8.2, 8.4, 9; VCAP class Enterprise service; VCAP-EI class Enterprise Service |
| **Verifier** | Credential verifier and relying party | Sections 7, 8.3, 8.4 |

A product claims conformance for each class it implements. The optional authenticator features of VCAP §2.1 (USB HID, NFC and USB CCID transports, WebAuthn route, group member signing) are declared with the claim.

### 11.2 VAF-BASE-1

An implementation claiming `VAF-BASE-1` MUST satisfy the following requirements for its class:

| ID | Class | Requirement | Evidence or limit |
| --- | --- | --- | --- |
| VAF-BASE-01 | Authenticator | Authenticator-generated, non-exportable Ed25519 identity keys | `CreateIdentity`, KERI `icp` binding |
| VAF-BASE-02 | Authenticator | Four isolated CLIENT/WORK slots, constrained operations | `GetState`, allowed owner/kind matrix |
| VAF-BASE-03 | Authenticator | Enterprise binding until Reset and signed TrustConfig | `BindEnterprise`, `Personalize` |
| VAF-BASE-04 | Authenticator | PIN token authorization and a new UP for each signature, with a touch sensor and presence indicator | `ClientPIN`, `Sign`, `UploadEnd` |
| VAF-BASE-05 | Authenticator | Challenge-bound signed device state | `GetState` / `StateProof` |
| VAF-BASE-06 | Authenticator | Message- and key-bound enterprise Ticket enforcement | Ticket verification and `KeyRef` |
| VAF-BASE-07 | Authenticator | Single-key, single-head KERI `ICP` / `IXN` / WORK `ROT` in the event syntax of VCAP §8.4.3 | Local KEL checks and atomic state |
| VAF-BASE-08 | Authenticator | Exactly-once local KEL head advancement and latest-event signature recovery | `Recover` for the latest KEL event |
| VAF-BASE-09 | Authenticator | Explicit reset epoch, irreversible reset and failure handling | `Reset`, `RECOVERY_REQUIRED` |
| VAF-BASE-10 | Authenticator | At least one VCAP transport, declared in GetInfo | CTAPHID over USB HID, the CTAP NFC binding, or USB CCID |
| VAF-BASE-11 | Authenticator | Documented security limits and privacy controls | Threat model and product documentation (Section 9.2) |
| VAF-BASE-12 | Platform, Enterprise Service | Separation of device signing, enterprise archiving and network verification, with per-stage status | Integration and negative tests |
| VAF-BASE-13 | Enterprise Service | Ticket issuance per Section 8.2 and VCAP-EI | VCAP-EI conformance tests |
| VAF-BASE-14 | Enterprise Service, Platform | Handling of device loss and Reset | Section 6.5 |

`VAF-BASE-1` covers single-key personal AIDs. Participation in group AIDs is `VAF-GROUP-1` (Section 11.4). Delegated events, on-device ACDC verification, anchored presentations, IPEX operation recovery and in-place enterprise root rotation belong to the candidate profiles below.

### 11.3 Candidate extension profiles

- **VAF-IPEX-1** — complete hardware-assisted IPEX Grant/Admit signing and operation-recovery semantics.
- **VAF-PRES-1** — signed/anchored presentation assurance: ordinary operations use a signed holder proof, high-risk operations require verified KERI anchoring, and a verifier reports `Anchored` only after verifying the anchor; with privacy-related disclosure requirements.
- **VAF-POLICY-1** — enterprise risk classes LOW (short-lived read-only access), MEDIUM (ordinary signing and credential presentation) and HIGH (privileged operations or anchored presentations); a central PDP decides, a LOW read-only decision may be cached under a scoped, time-limited lease, and every HIGH operation receives a fresh online decision.

These profiles are not specified by VAF 1.0; a product can claim one only after it is specified.

### 11.4 VAF-GROUP-1

`VAF-GROUP-1` builds on `VAF-BASE-1`: an implementation claiming it MUST also claim `VAF-BASE-1` for the same class, and MUST satisfy the following requirements:

| ID | Class | Requirement | Evidence or limit |
| --- | --- | --- | --- |
| VAF-GROUP-01 | Authenticator | Group member signing of VCAP §2.1, declared by GetInfo option `vcapGroup` | VCAP §§ 7.1, 7.7 kinds 7, 8 and 9 |
| VAF-GROUP-02 | Authenticator | Member key and next-key commitment binding in group `icp` / `rot` | VCAP §8.4.4 item 4 |
| VAF-GROUP-03 | Authenticator | At most one event per (slot, group AID, sequence number), increasing sequence numbers, prior-SAID check for the following sequence number, `GROUP_SUPERSEDE` only at the record's own sequence number with the same prior event and at most once per sequence number, or to reuse an abandoned inception record; `GROUP_EXN` only for a recorded group AID; group records committed atomically with the slot | VCAP §8.4.4 items 5–6, §8.5.4, §8.7 |
| VAF-GROUP-04 | Authenticator | Group record state in `StateProof` and recovery of the recorded signature | VCAP §§ 7.4.2, 7.8, 9.3 |
| VAF-GROUP-05 | Enterprise Service | Group Ticket issuance per VCAP §12.8 item 7 and VCAP-EI §§ 7.5, 7.15, including group messages (purposes 6, 20, 21) | VCAP-EI conformance tests |
| VAF-GROUP-06 | Enterprise Service | `GROUP_SUPERSEDE` confined to a separately controlled role key, with a recorded determination per use | Audit records |
| VAF-GROUP-07 | Platform, Enterprise Service | Group participation and per-stage status (member signed, threshold met, network accepted or delivered, abandoned) | VCAP §12.10, VCAP-EI §§ 7.17, 9.6 |
| VAF-GROUP-08 | Enterprise Service, Platform | Device loss and Reset of a member: the affected member key is reported as lost to the other members, so that the group rotates it out | Section 6.5 item 7 |
| VAF-GROUP-09 | Enterprise Service | A member's own rotation coordinated with the rotations of its groups | VCAP §12.8 item 7.7 |

A Reset deletes the slot's group records together with its keys (VCAP §5.2). Because a group's continuity does not depend on any single member, a group can survive the loss of a member's authenticator by rotating that member out with the remaining members' signatures, provided its thresholds allow it; the Enterprise Service SHOULD choose thresholds with that in mind.

## 12. Conformance tests

Byte-exact test vectors for the derivations and structures of VCAP Sections 6, 8 and 9 and for the event syntax of VCAP §8.4.3 are given in VCAP Appendix E. A test suite for `VAF-BASE-1` MUST include at least the following cases, each with positive and negative tests, and an implementation claiming `VAF-BASE-1` MUST pass them for its class:

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
| BASE-T10 | Physical reset destroys prior-epoch secrets, removes the enterprise binding, keeps the attestation identity and increments `resetEpoch`. |
| BASE-T11 | Malformed persistent state leads to `RECOVERY_REQUIRED`. |
| BASE-T12 | The verifier rejects missing credential status, an invalid chain or an unverified anchored claim. |
| BASE-T13 | After a reported device loss, the Enterprise Service refuses Tickets for the device and reports its AIDs as inactive. |
| BASE-T14 | An event that deviates from the syntax of VCAP §8.4.3 (whitespace, field order, `s` encoding, escapes) is rejected with `INVALID_KERI_EVENT`. |

An implementation claiming `VAF-GROUP-1` MUST in addition pass the following cases:

| Case | Expected outcome |
| --- | --- |
| GROUP-T01 | A group `icp` with the slot's current key in `k` and its next-key commitment in `n` is signed and creates a group record; one without either is rejected with `KEY_BINDING`. |
| GROUP-T02 | A group event whose `i` is the AID of any slot is rejected with `KEY_BINDING`. |
| GROUP-T03 | Any event of the same group AID at the recorded or a lower sequence number, including the recorded event itself, is rejected with `INVALID_STATE` under kind `GROUP`. |
| GROUP-T04 | An event at the following sequence number whose `p` is not the recorded SAID is rejected; an event at a later sequence number is signed. |
| GROUP-T05 | `GROUP_SUPERSEDE` signs one replacement at the recorded sequence number, sets `replaced` and increments `supersedeCount`; a second replacement at the same sequence number, one at any other sequence number, and one without capability bit 15 are rejected. |
| GROUP-T06 | A lost group response is resolved by a `StateProof` carrying the group record and the exact `Recover` result, also after a later EXN signature. |
| GROUP-T07 | A third group AID on one slot is rejected with `NO_SPACE`, and a group AID already recorded on another slot with `KEY_BINDING`; power loss during a group signature leaves the slot with both its counter and its group record either before or after the signature; Reset deletes all group records. |
| GROUP-T08 | The Enterprise Service refuses a second original for the same (group AID, sequence number) and a group event that does not extend the accepted key state. |
| GROUP-T09 | A group event with a `k` entry other than a 44-byte `D` key, an `n` entry other than a 44-byte `E` digest, or type `dip` / `drt` is rejected with `INVALID_KERI_EVENT`; one with a weighted threshold array is signed. |
| GROUP-T10 | A group `ixn` on a slot without a record for the group AID is signed and creates a record; `GROUP_EXN` for a recorded group AID is signed and leaves the record unchanged, without a record it is rejected with `INVALID_STATE`, and with `i` equal to a slot AID with `KEY_BINDING`. |
| GROUP-T11 | `GROUP_SUPERSEDE` whose `p` differs from the replaced event's is rejected; with every record in use, `GROUP_SUPERSEDE` of a new group `icp` replaces the abandoned inception record with the lowest `signCounter` and shows the reuse with `replaced` set and `supersedeCount` 1, and is rejected when no record has `t = icp` and `seq = 0`. |
| GROUP-T12 | The Enterprise Service refuses a WORK `ROT` Ticket that would leave the slot outside the latest next-key commitment of one of its groups, and approves a joining member's signature on a group `rot` authorized by the other signers. |
| GROUP-T13 | The platform encodes member signatures with the CESR codes of VCAP §9.4 for `icp`, `ixn`, `rot` with equal and different indices, a joining member's `rot`, and a group `exn`. |

Transport tests additionally cover, for each declared transport, CTAPHID channel allocation, CCID card-session handling, multi-frame packet reconstruction, busy-state isolation between held and non-held contexts, keepalive and cancel semantics, NFC command chaining, negative framing tests and cross-transport transaction-recovery tests.

## 13. Versioning

Changes to VAF identity and security semantics, VCAP command bytes or transport framing require a new version of the affected document. Domain separators and codepoints change only through a versioned migration.

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
| Conformance classes and optional features | § 2.1 |
| KERI event syntax and encodings | §§ 6.2, 6.4, 8.4.3 |
| Transport | § 11 (11.1 message encoding, 11.2 CTAPHID, 11.3 NFC, 11.4 USB CCID) |
| Group member signing (`VAF-GROUP-1`) | §§ 5.2, 7.4.2, 7.7, 7.8, 7.14.5, 8.4.4, 8.5.4, 8.7, 9.3, 9.4, 12.3, 12.8 item 7, 12.10, 13.1, 13.2 item 8 |
| Delegation and IPEX boundaries | §§ 8.4.2, 8.5, 12.3 |

## B. References

### B.1 Normative references

[KERI], [CESR] and [ACDC] are working specifications without a stable version. VAF depends on them only for the event syntax and encodings fixed by VCAP §6.2–§6.4 and §8.4.3, which VCAP Appendix E pins byte for byte; a conformance claim states the versions it was tested against.

- [BCP14] RFC 2119 and RFC 8174 — <https://www.rfc-editor.org/info/bcp14/>
- [KERI] ToIP KERI working specification — <https://github.com/trustoverip/kswg-keri-specification>
- [CESR] ToIP CESR working specification — <https://github.com/trustoverip/kswg-cesr-specification>
- [ACDC] ToIP ACDC working specification — <https://github.com/trustoverip/kswg-acdc-specification>
- [vLEI-EGF] GLEIF vLEI Ecosystem Governance Framework — <https://www.gleif.org/en/organizational-identity/become-a-vlei-issuer-qvi/vlei-ecosystem-governance-framework>
- [VCAP] *vLEI Client to Authenticator Protocol (VCAP) 1.0* — <https://vlei-auth.github.io/vcap/>
- [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — <https://www.rfc-editor.org/rfc/rfc8032>
- [CTAP] FIDO Alliance, *Client to Authenticator Protocol v2.3* — <https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html>
- [VCAP-EI] [VCAP-EI 1.0](https://vlei-auth.github.io/vcap-ei/) — VCAP Enterprise Interface.
- [CCID] USB Implementers Forum, *Device Class Specification for USB Chip/Smart Card Interface Devices*, Revision 1.1.

### B.2 Informative references

- [WEBAUTHN] W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3* — <https://www.w3.org/TR/webauthn-3/>
