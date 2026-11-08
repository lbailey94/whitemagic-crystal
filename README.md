# whitemagic-crystal

Sovereign client-side encrypted memory crystals for autonomous AI agents.

## Overview

`whitemagic-crystal` guarantees that agent memories are sealed locally on-device using authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) before being synced to any hosted vault, relay, or cloud storage.

The remote server only ever sees:
- Tenant hash (salted identifier)
- Cryptographic ciphertext & authentication tag
- Content-addressed ID (`sha256:...`)
- Lineage parent ID (hash-chained)
- Verifiable Ed25519 envelope signature

Plaintext never leaves the agent's local host unencrypted.

## Installation

```bash
pip install -e /home/lucas/tools/whitemagic-crystal
```

## Quickstart

```python
from whitemagic_crystal import CrystalClient

# 1. Initialize client with a tenant ID
client = CrystalClient(
    tenant_id="sol-agent-1",
    auth_token="<your-wm-token>", # or set WM_HOSTED_TOKEN
)

# 2. Seal plaintext into an encrypted envelope
envelope = client.seal(
    "Critical task discovery: production database uses Landlock LSM sandbox."
)
print("Sealed Crystal ID:", envelope["id"])

# 3. Push to hosted vault
client.push(envelope)

# 4. Pull and unseal locally
envelope, plaintext = client.pull_text(envelope["id"])
print("Decrypted Plaintext:", plaintext)
```

## CLI Usage

```bash
# Generate key
whitemagic-crystal keygen --cipher AES-256-GCM

# Seal local file
whitemagic-crystal seal --tenant my-agent --key-hex <key> input.txt > crystal.json

# Unseal envelope
whitemagic-crystal unseal --key-hex <key> crystal.json
```

## License

MIT
