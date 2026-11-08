#!/usr/bin/env python3
"""Demonstration of end-to-end agent memory using whitemagic-crystal."""

from whitemagic_crystal import CrystalClient
from whitemagic_crystal.adapters import SessionMemoryManager


def main():
    print("Initializing Sovereign Crystal Client...")
    client = CrystalClient(tenant_id="sol-autonomous-agent")
    print(f"  Tenant Hash: {client.tenant_hash}")
    print(f"  Exported Key (Base64): {client.key_base64[:12]}...")

    manager = SessionMemoryManager(session_id="expedition-042", client=client)

    print("\n[Step 1] Appending conversational turns to encrypted session...")
    t1 = manager.append("user", "What is the security boundary of WhiteMagic Gen 3?")
    print(f"  Turn 1 sealed into Crystal ID: {t1['id']}")

    t2 = manager.append(
        "assistant",
        "WhiteMagic Gen 3 executes in a deterministic Linux Landlock LSM sandbox with zero outbound network egress.",
    )
    print(f"  Turn 2 sealed into Crystal ID: {t2['id']}")
    print(f"    Parent Crystal Link: {t2['parent_crystal_id']}")

    print("\n[Step 2] Formatting decrypted context prompt for LLM call:")
    print("--------------------------------------------------")
    print(manager.format_context_prompt())
    print("--------------------------------------------------")

    print("\n[Step 3] Emitting a signed milestone checkpoint...")
    checkpoint = manager.commit_checkpoint("Verified Linux Landlock LSM sandbox security properties.")
    print(f"  Checkpoint Crystal ID: {checkpoint['id']}")
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
