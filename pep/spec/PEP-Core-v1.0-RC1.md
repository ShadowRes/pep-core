# PEP Protocol Core Specification v1.0-RC1

**Status:** FINAL RELEASED  
**Specification Family:** PEP Protocol  
**Core Version:** v1.0-RC1  
**Serialization:** Strict Canonical Binary  
**Signature Algorithm:** Ed25519  
**Document Role:** Normative Protocol Specification

---

## 1. Scope & System Boundaries

This specification defines the normative rules governing:

- Transaction structure
- Canonical binary serialization
- Domain separation
- Chain binding
- Cryptographic verification
- Account/public-key binding
- Sequence semantics
- Balance transitions
- Fee accounting
- Atomic state transitions
- Supply/conservation invariants
- Error semantics
- Conformance requirements

The following are explicitly outside the Core specification:

- P2P transport
- Socket/network implementation
- RPC
- Wallet UI
- Database implementation
- Node deployment
- Consensus/network topology

---

## 2. Terminology & Data Types

### 2.1 Address
- Size: 32 bytes
- Representation: Raw binary

### 2.2 Ed25519 Public Key
- Size: 32 bytes
- Representation: Raw binary

### 2.3 Ed25519 Signature
- Size: 64 bytes
- Representation: Raw binary

### 2.4 Amount
- Type: uint64
- Width: 8 bytes
- Byte order: Big-Endian

### 2.5 Fee
- Type: uint64
- Width: 8 bytes
- Byte order: Big-Endian

### 2.6 Sequence
- Type: uint64
- Width: 8 bytes
- Byte order: Big-Endian

### 2.7 Nonce
- Size: 16 bytes
- Representation: Raw binary cryptographic entropy

---

## 3. Protocol Constants & Encodings

### 3.1 Domain Separator
- String Value: `PEP-TX-V1`
- Canonical Encoding: Exact 12 bytes fixed-width, ASCII encoded, null-padded (`0x00`).
- Hex Representation: `50 45 50 2d 54 58 2d 56 31 00 00 00`

### 3.2 Network Chain ID
- String Value: `PEP-MAINNET-01`
- Canonical Encoding: Exact 16 bytes fixed-width, ASCII encoded, null-padded (`0x00`).
- Hex Representation: `50 45 50 2d 4d 41 49 4e 4e 45 54 2d 30 31 00 00`
- Rule: Active Chain ID MUST be obtained strictly from state context. Transactions CANNOT override Chain ID.

---

## 4. Transaction & Fee Model

### 4.1 Fee Distribution Logic
Fee integer division is strictly deterministic across implementations:

$$\text{dev\_fee} = \lfloor \frac{\text{fee} \times 15}{100} \rfloor$$
$$\text{node\_fee} = \text{fee} - \text{dev\_fee}$$

### 4.2 Conservation
Accounting Invariant MUST satisfy: $\text{dev\_fee} + \text{node\_fee} \equiv \text{fee}$.
No rounding error may create or destroy value.

---

## 5. Canonical Binary Serialization

Canonical Payload Layout (Exact Offset Mapping):

| Offset (Bytes) | Length | Field | Encoding |
| :--- | :--- | :--- | :--- |
| `0x00` | 12 | `domain_separator` | Raw Bytes (`PEP-TX-V1\0\0\0`) |
| `0x0C` | 16 | `chain_id` | Raw Bytes (`PEP-MAINNET-01\0\0`) |
| `0x1C` | 32 | `sender` | Raw Bytes (32-byte Address) |
| `0x3C` | 32 | `recipient` | Raw Bytes (32-byte Address) |
| `0x5C` | 8 | `amount` | uint64 BE |
| `0x64` | 8 | `fee` | uint64 BE |
| `0x6C` | 8 | `sequence` | uint64 BE |
| `0x74` | 16 | `nonce` | Raw Bytes (16-byte Entropy) |

Total Payload Length = Exact 132 Bytes.

---

## 6. Account / Public-Key Lifecycle (v1.0 Bound)

- **Binding Rule:** $\text{Address} \equiv \text{SHA256}(\text{Public\_Key})$
- **Lifecycle Limitation:** Key rotation/revocation is OUT OF SCOPE for Core v1.0. The first bound key is immutable for the account lifetime in v1.0.

---

## 7. Sequential Validation Pipeline

Pipeline Execution Order:
1. Structural Validation (Exact 132-byte payload check)
2. Type / Range Validation
3. Chain ID Binding Match
4. Account Lookup
5. Sequence Validation ($N + 1$)
6. Cryptographic Verification (Ed25519)
7. Balance & Fee Validation
8. Atomic State Transition
9. Supply Invariant Check
10. Commit

Any failure results in immediate REJECT with ZERO state mutation.

---

## 8. Error Code Registry

- `0x00` → `ERR_TRANSACTION_REJECTED` (External Facing Generic Failure)
- `0x01` → `ERR_MALFORMED_BINARY`
- `0x02` → `ERR_OUT_OF_BOUNDS`
- `0x03` → `ERR_CHAIN_ID_MISMATCH`
- `0x04` → `ERR_ACCOUNT_NOT_FOUND`
- `0x05` → `ERR_SEQUENCE_GAP`
- `0x06` → `ERR_SEQUENCE_REPLAY`
- `0x07` → `ERR_SIGNATURE_VERIFICATION_FAILED`
- `0x08` → `ERR_INSUFFICIENT_FUNDS`
- `0x09` → `ERR_INVARIANT_BROKEN`

---

## 9. Specification Status

Status: **FINAL RELEASED (v1.0)**
