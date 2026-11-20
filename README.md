# whitemagic-crystal

Sovereign client-side encrypted memory crystals for autonomous AI agents.

## Quickstart

With Python 3.10 or newer, install the published package in a virtual environment. The example seals and opens a test note locally with no account or hosted token. After installation, it can run offline.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install whitemagic-crystal==0.1.1
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

The test key lives only in this process. To reopen saved records, keep the original key in protected storage with a recovery copy. Provide the key as 32 bytes via `key=` or as base64 via `WM_CRYSTAL_KEY`. In 0.1.x, omitting both causes the client to generate a new key.

## Overview

`whitemagic-crystal` seals content locally with authenticated encryption (AES-256-GCM or ChaCha20-Poly1305). An envelope can expose a tenant or owner locator, ciphertext and authentication tag, content and lineage IDs, public metadata such as tags, and an optional Ed25519 signature. Keep secret values out of public metadata.

## CLI usage

Use the Python example to seal a note offline. The CLI's `seal` command looks up the gateway-assigned owner locator using a provisioned `WM_CRYSTAL_TOKEN` or a protected `--token-file`. See [hosted Crystal access](https://www.whitemagic.dev/hosted#crystals) for current provisioning details.

```bash
# Generate a protected key file
.venv/bin/whitemagic-crystal genkey --out crystal.key

# Seal a file for a provisioned owner
.venv/bin/whitemagic-crystal seal --file input.txt --key crystal.key --out crystal.json

# Open the saved envelope locally
.venv/bin/whitemagic-crystal unseal --envelope crystal.json --key crystal.key
```

Version 0.1.1 updates installation and usage documentation. Its runtime code matches 0.1.0.

## License

MIT
