# whitemagic-crystal

Sovereign client-side encrypted memory crystals for autonomous AI agents.

## Overview

`whitemagic-crystal` seals content locally with authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) before using this client to send an envelope to a hosted vault. Callers remain responsible for protecting plaintext and retaining the encryption key.

The underlying format also supports erasure-aware set commitments (`wm.crystal-set-commitment`) and signed deletion tombstones (`wm.crystal-erasure`). Detecting rollback or erasure resurrection requires the relying party to verify suitable independently retained, current commitments and tombstones; encrypting a single envelope does not establish those properties.

An envelope can disclose:
- Tenant / owner scope locator (authenticated registry mapping)
- Cryptographic ciphertext, nonce & authentication tag (`aes-256-gcm` or `chacha20-poly1305`)
- Content-addressed ID (`sha256:...`)
- Lineage parent ID (hash-chained)
- Public metadata, including tags, when supplied
- An Ed25519 client signature, only if a signing key is configured and signing is not disabled

The client does not put the plaintext or encryption key in the envelope. Avoid putting secrets in public metadata. An unsigned envelope has no signer identity; a valid signature alone does not establish that its signer is trusted.

## Installation

```bash
pip install whitemagic-crystal
# Or from a local checkout:
pip install -e .
```

## Quickstart

First generate a 32-byte encryption key with a trusted random generator and retain it in your secret manager, with a protected recovery backup. Supply the **same** key on each run as base64 in `WM_CRYSTAL_KEY`, or pass its bytes as `key=` from your secret manager. Configure the environment through your deployment's secret mechanism rather than pasting the key into source code or shell history. Treat access to that key as access to the encrypted memories.

```python
from whitemagic_crystal import CrystalClient

# 1. Initialize using the retained WM_CRYSTAL_KEY.
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

Without the original key, a later process cannot decrypt existing envelopes; the hosted service cannot recover it for you. If a previous v0.1.0 run used its generated key, save that run's `client.key_base64` securely **while the client is still alive**. Do not print or transmit the key. If the process ended without retaining it, the client cannot reconstruct it from an envelope.

For an explicitly disposable local demonstration, use `CrystalClient(tenant_id="demo", ephemeral=True)`. Do not rely on that key for long-lived data. `ephemeral=True` is a fallback when neither `key` nor `WM_CRYSTAL_KEY` is supplied; an explicitly supplied key or environment key takes precedence.

### Migrating from 0.1.0

Creating a client with no key previously generated a new key silently. This unreleased `0.2.0.dev0` candidate deliberately raises `ValueError` instead; pass a retained key or opt into `ephemeral=True`. This is a breaking API change and must be called out in the next release and its versioning decision. The included demo and benchmark opt into ephemeral keys; adapters receive the caller's configured `CrystalClient` and do not create keys themselves.

Signatures are optional by default. Provide a separate 32-byte Ed25519 private seed as hex via `signing_key_hex` or `WM_CRYSTAL_SIGNING_KEY` to sign new envelopes. `seal(sign=True)` requires one; `seal(sign=False)` deliberately skips signing. Keep the signing seed separate from the encryption key. Signing does not establish the signer's authorization, capture completeness, or actual execution.

The prior `verify_set(envelopes, expected_root)` method was nonfunctional. It now takes a signed commitment object and a caller-pinned `anchor_public_key` keyword, and raises on failure. The commitment and key must come from an independently retained trusted source; the caller must also determine whether the commitment is current. Matching the committed prefix does not establish freshness, authorized signers, deletion, or complete server history. Unversioned unsigned envelopes do not authenticate public metadata such as tags.

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
