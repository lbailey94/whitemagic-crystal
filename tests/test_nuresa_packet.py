from __future__ import annotations

import hashlib
import math
import tempfile
from pathlib import Path

import pytest

from whitemagic_crystal.core import LocalCrystalStore, generate_key
from whitemagic_crystal.nuresa_packet import (
    GANA_OPCODES,
    GEN4_DIM,
    VALK4_MAX_PACKET_BYTES,
    compose_valk4_orthogonal,
    pack_valk4_packet,
    parse_valk4_packet,
    seal_and_verify_valk4_in_store,
)


def _norm(v: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in v))
    return [x / n for x in v]


def _make_skill_packet(op_start: int, count: int, seed_offset: int, tag: str) -> bytes:
    vault_c = [[0.0] * GEN4_DIM for _ in range(GANA_OPCODES)]
    regs_m = [0.0] * GANA_OPCODES
    mask = 0
    engrams: list[tuple[bytes, int]] = []
    for idx, k in enumerate(range(op_start, op_start + count)):
        vec = [0.0] * GEN4_DIM
        block = (idx * 2) if op_start == 0 else (20 + idx * 2)
        vec[block] = 2.4
        vec[block + 1] = 1.6
        for d in range(40, 64):
            vec[d] = 0.55 * math.cos((k + seed_offset + d) * 0.31)
        vault_c[k] = _norm(vec)
        regs_m[k] = 1.45
        mask |= 1 << k
        engrams.append((hashlib.sha256(f"{tag}:{k}".encode()).digest()[:3], k))
    origin = [0.02 if i % 2 == 0 else -0.01 for i in range(GEN4_DIM)]
    return pack_valk4_packet(
        origin=origin,
        vault_c=vault_c,
        registers_m=regs_m,
        committed_mask=mask,
        engrams=engrams,
    )


def test_valk4_orthogonal_compose_and_crystal_anchor_seal():
    pkt_a = _make_skill_packet(0, 10, 0, "skill_a_kekkai")
    pkt_b = _make_skill_packet(14, 10, 7, "skill_b_poincare")

    assert len(pkt_a) <= VALK4_MAX_PACKET_BYTES
    assert len(pkt_b) <= VALK4_MAX_PACKET_BYTES

    composed, meta = compose_valk4_orthogonal(pkt_a, pkt_b)
    assert meta["within_64k_sram_limit"] is True
    assert len(composed) <= VALK4_MAX_PACKET_BYTES
    assert meta["max_subspace_cross_dot"] < 1e-5
    assert meta["engrams_count"] == 20

    parsed = parse_valk4_packet(composed)
    for k in range(0, 10):
        assert parsed.is_committed(k)
    for k in range(14, 24):
        assert parsed.is_committed(k)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = LocalCrystalStore(
            root / "store",
            key=generate_key(),
            tenant_id="stage4c-nuresa",
            anchor_base_dir=root / "anchors",
        )
        receipt = seal_and_verify_valk4_in_store(store, composed, skill_label="skill_a_plus_b_orth")
        assert receipt["within_64k_sram_limit"] is True
        assert receipt["packet_bytes"] == len(composed)


def test_valk4_rejects_oversized_packet():
    with pytest.raises(ValueError, match="exceeds"):
        parse_valk4_packet(b"VALK4\x00\x02\x03" + b"\x00" * VALK4_MAX_PACKET_BYTES)
