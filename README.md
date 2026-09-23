# Physical Entropy Protocol (PEP) Core

PEP is a lightweight physical entropy encryption module designed for constrained environments.

## Core Features
- **Execution Jitter Entropy:** Physical seed extraction via microsecond nanosecond timing variances.
- **HKDF Key Strengthening:** Uses HMAC-SHA256 key derivation to secure session tokens.
- **Zeroization Architecture:** Explicit memory reference cleanup using python garbage collection routines.

## Running locally
```bash
python main.py

