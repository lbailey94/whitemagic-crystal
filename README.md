# whitemagic-crystal

Sovereign client-side encrypted memory crystals for autonomous AI agents.

## Quickstart

With Python 3.10 or newer, install the [published 0.1.0 package](https://pypi.org/project/whitemagic-crystal/0.1.0/) in a virtual environment. The example seals and opens a test note locally with no account or hosted token. After installation, it can run offline.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install whitemagic-crystal==0.1.0
.venv/bin/python - <<'PY'
from secrets import token_bytes
from whitemagic_crystal import CrystalClient

note = b"The first Crystal note is violet."
client = CrystalClient(tenant_id="quickstart", key=token_bytes(32))
envelope = client.seal(note, sign=False)
assert client.unseal(envelope) == note
print("Opened the original note.")
PY
```

The test key lives only in this process. For records you plan to reopen, retain the original key securely and keep a protected recovery copy. See [hosted Crystal access](https://www.whitemagic.dev/hosted#crystals) for the separate provisioned vault workflow.

## Overview

`whitemagic-crystal` seals content locally with authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) before using this client to send an envelope to a hosted vault. Callers remain responsible for protecting plaintext and retaining the encryption key.

The underlying format also supports erasure-aware set commitments (`wm.crystal-set-commitment`) and signed deletion tombstones (`wm.crystal-erasure`). Detecting rollback or erasure resurrection requires the relying party to verify suitable independently retained, current commitments and tombstones; encrypting a single envelope does not establish those properties.

### Independent AGMI Scorecard Verification (2026-11-17)

On November 17, 2026, Agent Memory Integrity (`agmi`) maintainer Yasha Khandelwal [independently reproduced the fixture results](https://github.com/tech4biz-yasha/agent-memory-integrity/pull/14#issuecomment-6950392476) against [`crystal_client.py` at `273b177b`](https://github.com/lbailey94/whitemagic/blob/273b177b5c59eb3148b721a85683ab929041d246/scripts/crystal_client.py) and published three live scorecard rows:
- **[Default local store (`10/10` rejected on verified read)](https://agentmemoryintegrity.org/stores/whitemagic-crystals.html)** — with the current commitment retained outside the store (default off-store anchor policy).
- **[In-store anchor comparison (`8/10` rejected on verified read)](https://agentmemoryintegrity.org/stores/whitemagic-crystals-in-store.html)** — when the commitment lives inside the same mutable directory (`T6` snapshot rollback and `T10` erasure resurrection require an off-store anchor).
- **[Ciphertext audit without KEK (`10/10` reported during audit)](https://agentmemoryintegrity.org/stores/whitemagic-crystals-ciphertext-audit.html)** — integrity and commitment verification without key-encryption-key access (audit reporting, distinct from verified plaintext read refusal).

An envelope can disclose:
- Tenant / owner scope locator (authenticated registry mapping)
- Cryptographic ciphertext, nonce & authentication tag (`aes-256-gcm` or `chacha20-poly1305`)
- Content-addressed ID (`sha256:...`)
- Lineage parent ID (hash-chained)
- Public metadata, including tags, when supplied
- An Ed25519 client signature, only if a signing key is configured and signing is not disabled

The client does not put the plaintext or encryption key in the envelope. Avoid putting secrets in public metadata. An unsigned envelope has no signer identity; a valid signature alone does not establish that its signer is trusted.

## Installation

The hosted example below uses the unreleased `0.2.0.dev0` source. To review or use this candidate, install this checkout in an isolated Python environment:

```bash
python -m pip install .
# For development in this checkout:
python -m pip install -e .
```

## Hosted quickstart for the source candidate

First generate a 32-byte encryption key with a trusted random generator and retain it in your secret manager, with a protected recovery backup. Supply the **same** key on each run as base64 in `WM_CRYSTAL_KEY`, or pass its bytes as `key=` from your secret manager. Configure the environment through your deployment's secret mechanism rather than pasting the key into source code or shell history. Treat access to that key as access to the encrypted memories.

```python
from whitemagic_crystal import CrystalClient, fetch_owner_locator

# Fetch the gateway-assigned locator explicitly, after authentication.
# This makes a network request; do not use it for an offline-only example.
token = "<your-wm-token>"
owner = fetch_owner_locator(auth_token=token)

# 1. Initialize using the retained WM_CRYSTAL_KEY.
client = CrystalClient(
    tenant_id="sol-agent-1",
    auth_token=token, # or set WM_HOSTED_TOKEN
    owner_locator=owner,
)

# 2. Seal plaintext into an encrypted envelope
envelope = client.seal(
    "Critical task discovery: production database uses Landlock LSM sandbox."
)
print("Sealed Crystal ID:", envelope["crystal_id"])

# 3. Push to hosted vault
client.push(envelope)

# 4. Pull and unseal locally
envelope, plaintext = client.pull_text(envelope["crystal_id"])
print("Decrypted Plaintext:", plaintext)
```

Without the original key, a later process cannot decrypt existing envelopes; the hosted service cannot recover it for you. If a previous v0.1.0 run used its generated key, save that run's `client.key_base64` securely **while the client is still alive**. Do not print or transmit the key. If the process ended without retaining it, the client cannot reconstruct it from an envelope.

For an explicitly disposable local demonstration, use `CrystalClient(tenant_id="demo", ephemeral=True)`. Do not rely on that key for long-lived data. `ephemeral=True` is a fallback when neither `key` nor `WM_CRYSTAL_KEY` is supplied; an explicitly supplied key or environment key takes precedence.

### Migrating from 0.1.0

Creating a client with no key previously generated a new key silently. This unreleased `0.2.0.dev0` candidate deliberately raises `ValueError` instead; pass a retained key or opt into `ephemeral=True`. This is a breaking API change and must be called out in the next release and its versioning decision. The included demo and benchmark opt into ephemeral keys; adapters receive the caller's configured `CrystalClient` and do not create keys themselves.

Signatures are optional by default. Provide a separate 32-byte Ed25519 private seed as hex via `signing_key_hex` or `WM_CRYSTAL_SIGNING_KEY` to sign new envelopes. `seal(sign=True)` requires one; `seal(sign=False)` deliberately skips signing. Keep the signing seed separate from the encryption key. Signing does not establish the signer's authorization, capture completeness, or actual execution.

The prior `verify_set(envelopes, expected_root)` method was nonfunctional. It now takes a signed commitment object and a caller-pinned `anchor_public_key` keyword, and raises on failure. The commitment and key must come from an independently retained trusted source; the caller must also determine whether the commitment is current. Matching the committed prefix does not establish freshness, authorized signers, deletion, or complete server history. Unversioned unsigned envelopes do not authenticate public metadata such as tags.

The candidate uses `crystal_id` as its envelope identifier; the former `id` alias is removed because the gateway does not preserve it in signed envelopes. Hosted operations require the authenticated `owner_locator` and now default to `https://api.whitemagic.dev`; local-only clients may omit the locator. Do not assume a tenant label is the gateway-assigned locator. A pull with `auto_unseal=False` checks the returned ID and context labels but does not verify its ciphertext or signature. The hosted journey is covered by local mocks and source inspection only; a live hosted handshake remains unqualified.

Session adapters use process-local state by default. To retain history, the chain head, and uncertain pushes across restarts, pass `state_path=` to `SessionMemoryManager` or `CrystalChatMessageHistory`:

```python
from pathlib import Path
from whitemagic_crystal.adapters.generic import SessionMemoryManager

state_dir = Path.home() / ".local" / "state" / "my-agent-crystals"
state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
memory = SessionMemoryManager(
    "project-session", client, auto_push=True,
    state_path=state_dir / "session.sqlite3",
)
# Reopen with the same session, client context, and retained encryption key.
```

The state file contains encrypted history and pending envelopes, without the encryption key or hosted token. On POSIX, its existing parent must be owned by the current user with no group/other permissions; the database is created with mode `0600`. Symlink paths are refused. On other systems, protect the directory with the platform's access controls. Back up the database separately from the key using a consistent SQLite backup method or while all managers are closed. Losing either the database or key prevents this local restoration.

Before a push, the exact pending envelope is committed to SQLite. If `auto_push` raises, or the process exits while waiting for a response, reopening preserves that envelope and blocks new entries. Inspect `pending_envelope`, verify whether the gateway stored that exact crystal, then call `resolve_pending(confirmed_stored=True)` or, after establishing it was not stored, `resolve_pending(confirmed_stored=False)`. This method records the caller's verdict without contacting the gateway. A failed request alone does not establish absence. A local write failure after remote success also leaves the saved pending entry for reconciliation.

Revision checks reject writes from stale manager instances before sending another envelope; reopen to reload the latest local state. Use one owner per session to coordinate live requests and reconciliation. The journal does not establish remote freshness or prevent replay of an older valid database. `clear()` resets the local session (including the journal when configured) and does not delete hosted crystals. SQLite transaction recovery is used; power-loss behavior depends on the filesystem and storage. Public envelope tags still disclose session ID and message role.

## CLI usage

Use the Python example above to seal a note offline. The CLI's `seal` command looks up the gateway-assigned owner locator using a provisioned `WM_CRYSTAL_TOKEN` or a protected `--token-file`.

```bash
# Generate a key file for a new trial
whitemagic-crystal genkey --out crystal.key

# Seal a file for the authenticated owner
whitemagic-crystal seal --file input.txt --key crystal.key --out crystal.json

# Open the saved envelope locally
whitemagic-crystal unseal --envelope crystal.json --key crystal.key
```

## License

MIT
