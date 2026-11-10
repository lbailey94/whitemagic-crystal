#!/usr/bin/env python3
"""Demonstration of end-to-end agent memory using whitemagic-crystal."""

from whitemagic_crystal import CrystalClient
from whitemagic_crystal.adapters import SessionMemoryManager


def main():
    print("Initializing Sovereign Crystal Client...")
    # Disposable example only; persistent use must provide a retained key.
    client = CrystalClient(tenant_id="sol-autonomous-agent", ephemeral=True)
    print(f"  Tenant Hash: {client.tenant_hash}")
    print("  Using a disposable key for this run")

    manager = SessionMemoryManager(session_id="expedition-042", client=client)

    print("\n[Step 1] Appending conversational turns to encrypted session...")
    t1 = manager.append("user", "Remember the next project milestone.")
    print(f"  Turn 1 sealed into Crystal ID: {t1['crystal_id']}")

    t2 = manager.append(
        "assistant",
        "The next milestone is a local recovery test.",
    )
    print(f"  Turn 2 sealed into Crystal ID: {t2['crystal_id']}")
    print(f"    Parent Crystal Link: {t2['parent_crystal_id']}")

    print("\n[Step 2] Formatting decrypted context prompt for LLM call:")
    print("--------------------------------------------------")
    print(manager.format_context_prompt())
    print("--------------------------------------------------")

    print("\n[Step 3] Emitting an encrypted milestone checkpoint...")
    checkpoint = manager.commit_checkpoint("The next milestone is a local recovery test.")
    print(f"  Checkpoint Crystal ID: {checkpoint['crystal_id']}")
    print(f"  Committed Turn Count: 2")

    print("\n[Step 4] Tamper Verification Test:")
    tampered_env = dict(t2)
    tampered_env["parent_crystal_id"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    try:
        client.unseal(tampered_env)
        print("  ERROR: Tamper was not detected!")
    except Exception as e:
        print(f"  SUCCESS: Tamper detected immediately! ({e})")


if __name__ == "__main__":
    main()
