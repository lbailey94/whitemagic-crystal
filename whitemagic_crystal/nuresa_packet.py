"""NURESA (M register + C vault) and VALK4 orthogonal packet composition for whitemagic-crystal.

Provides wire-compatible parsing, construction, MGS2 orthogonal multi-skill composition
(A +_perp B), and encrypted/offstore-anchored sealing via ``LocalCrystalStore`` within
the hard ``<= 65,536`` byte VALK4 L1 SRAM packet ceiling.
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Any

from .core import LocalCrystalStore

VALK4_MAX_PACKET_BYTES = 65_536
VALK4_MAGIC = b"VALK4"
NUR4_MAGIC = b"NUR4"
GEN4_DIM = 64
GANA_OPCODES = 28
V1_FRAME_BYTES = 8 + (GEN4_DIM * 4) + (GEN4_DIM * GEN4_DIM) // 2  # 2312 bytes
NURESA_COMMIT_THRESHOLD = 0.85


@dataclass
class NuresaPacket:
    """Decoded VALK4 v2 + optional NUR4 NURESA neuron memory packet."""

    origin: list[float]
    primary_nonary: list[int]
    bayt_shells: list[list[int]]
    engrams: list[tuple[bytes, int]]
    registers_m: list[float]
    vault_c: list[list[float]]
    committed_mask: int
    raw_bytes: bytes

    def is_committed(self, op: int) -> bool:
        return 0 <= op < GANA_OPCODES and ((self.committed_mask >> op) & 1) == 1

    @property
    def byte_size(self) -> int:
        return len(self.raw_bytes)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw_bytes).hexdigest()


def _normalize(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(v * v for v in vec))
    if n <= 1e-12:
        return [0.0] * len(vec)
    return [v / n for v in vec]


def _scalar_to_nonary_nibble(v: float) -> int:
    if v >= 0.42:
        return 2  # +2
    if v >= 0.14:
        return 1  # +1
    if v <= -0.42:
        return 8  # -2
    if v <= -0.14:
        return 7  # -1
    if abs(v) > 0.03:
        return 3  # 0*
    return 0      # +0


def _nibble_to_gain(nib: int) -> float:
    return {0: 0.0, 1: 1.0, 2: 2.0, 3: 0.0, 4: 1.0, 5: 2.0, 6: 0.0, 7: -1.0, 8: -2.0}.get(nib, 0.0)


def _pack_nibbles(nibs: list[int]) -> bytes:
    buf = bytearray((len(nibs) + 1) // 2)
    for idx, nib in enumerate(nibs):
        v = nib & 0x0F
        if (idx & 1) == 0:
            buf[idx >> 1] |= v
        else:
            buf[idx >> 1] |= v << 4
    return bytes(buf)


def parse_valk4_packet(raw: bytes) -> NuresaPacket:
    """Parse and validate a binary VALK4 (+ optional NUR4 trailer) packet (<= 65,536 B)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("VALK4 packet must be bytes")
    data = bytes(raw)
    if len(data) > VALK4_MAX_PACKET_BYTES:
        raise ValueError(f"VALK4 packet {len(data)} B exceeds {VALK4_MAX_PACKET_BYTES} B limit")
    if len(data) < V1_FRAME_BYTES or data[:5] != VALK4_MAGIC:
        raise ValueError("Invalid VALK4 header or truncated v1 frame")

    origin = list(struct.unpack(f"<{GEN4_DIM}f", data[8 : 8 + GEN4_DIM * 4]))
    prim_off = 8 + GEN4_DIM * 4
    prim_nibs: list[int] = []
    for idx in range(GEN4_DIM * GEN4_DIM):
        b = data[prim_off + (idx >> 1)]
        prim_nibs.append((b >> ((idx & 1) * 4)) & 0x0F)

    vault_c: list[list[float]] = [
        [_nibble_to_gain(prim_nibs[k * GEN4_DIM + d]) * 0.5 for d in range(GEN4_DIM)]
        for k in range(GANA_OPCODES)
    ]
    registers_m = [0.0] * GANA_OPCODES
    committed_mask = 0
    bayt_shells: list[list[int]] = []
    engrams: list[tuple[bytes, int]] = []

    if data[6] >= 2 and len(data) >= V1_FRAME_BYTES + 8:
        shells_len, engram_len = struct.unpack("<II", data[V1_FRAME_BYTES : V1_FRAME_BYTES + 8])
        shells_start = V1_FRAME_BYTES + 8
        engram_start = shells_start + shells_len
        if len(data) < engram_start + engram_len:
            raise ValueError("Truncated VALK4 v2 shell/engram payload")

        shell_nibs = GANA_OPCODES * GEN4_DIM
        if shells_len >= (3 * shell_nibs) // 2:
            for s in range(3):
                s_vec: list[int] = []
                for i in range(shell_nibs):
                    gidx = s * shell_nibs + i
                    b = data[shells_start + (gidx >> 1)]
                    s_vec.append((b >> ((gidx & 1) * 4)) & 0x0F)
                bayt_shells.append(s_vec)

        cur = engram_start
        while cur + 4 <= engram_start + engram_len:
            engrams.append((data[cur : cur + 3], data[cur + 3] % GANA_OPCODES))
            cur += 4

        tr_off = engram_start + engram_len
        if len(data) >= tr_off + 8 + GANA_OPCODES * 4 and data[tr_off : tr_off + 4] == NUR4_MAGIC:
            committed_mask = struct.unpack("<I", data[tr_off + 4 : tr_off + 8])[0]
            pos = tr_off + 8
            registers_m = list(struct.unpack(f"<{GANA_OPCODES}f", data[pos : pos + GANA_OPCODES * 4]))
            pos += GANA_OPCODES * 4
            row_bytes = GEN4_DIM * 4
            while pos + 1 + row_bytes <= len(data):
                op = data[pos] % GANA_OPCODES
                pos += 1
                vault_c[op] = list(struct.unpack(f"<{GEN4_DIM}f", data[pos : pos + row_bytes]))
                pos += row_bytes
                committed_mask |= 1 << op

    return NuresaPacket(
        origin=origin,
        primary_nonary=prim_nibs,
        bayt_shells=bayt_shells,
        engrams=engrams,
        registers_m=registers_m,
        vault_c=vault_c,
        committed_mask=committed_mask,
        raw_bytes=data,
    )


def pack_valk4_packet(
    *,
    origin: list[float],
    vault_c: list[list[float]],
    registers_m: list[float],
    committed_mask: int,
    engrams: list[tuple[bytes, int]],
) -> bytes:
    """Serialize NURESA M/C vault state into a <= 65,536 B VALK4 v2 + NUR4 binary packet."""
    if len(origin) != GEN4_DIM or len(vault_c) != GANA_OPCODES or len(registers_m) != GANA_OPCODES:
        raise ValueError("Invalid NURESA dimensions")

    prim_nibs = [0] * (GEN4_DIM * GEN4_DIM)
    shell_rows = [0] * (GANA_OPCODES * GEN4_DIM)
    for k in range(GANA_OPCODES):
        for d in range(GEN4_DIM):
            nib = _scalar_to_nonary_nibble(vault_c[k][d])
            prim_nibs[k * GEN4_DIM + d] = nib
            shell_rows[k * GEN4_DIM + d] = nib

    packed_primary = _pack_nibbles(prim_nibs)
    packed_3shells = _pack_nibbles(shell_rows * 3)

    committed_ops = [k for k in range(GANA_OPCODES) if (committed_mask >> k) & 1]
    trailer_len = 8 + GANA_OPCODES * 4 + len(committed_ops) * (1 + GEN4_DIM * 4)
    static_len = 8 + GEN4_DIM * 4 + len(packed_primary) + 8 + len(packed_3shells) + trailer_len
    if static_len > VALK4_MAX_PACKET_BYTES:
        raise ValueError(f"Static VALK4 payload {static_len} exceeds {VALK4_MAX_PACKET_BYTES} B")

    max_engrams = (VALK4_MAX_PACKET_BYTES - static_len) // 4
    used_engrams = engrams[:max_engrams]
    engram_bytes = bytearray()
    for pref, op in used_engrams:
        if len(pref) != 3:
            raise ValueError("Engram prefix must be 3 bytes")
        engram_bytes.extend(pref)
        engram_bytes.append(op & 0xFF)

    buf = bytearray()
    buf.extend(b"VALK4\x00\x02\x03")
    buf.extend(struct.pack(f"<{GEN4_DIM}f", *origin))
    buf.extend(packed_primary)
    buf.extend(struct.pack("<II", len(packed_3shells), len(engram_bytes)))
    buf.extend(packed_3shells)
    buf.extend(engram_bytes)
    buf.extend(NUR4_MAGIC)
    buf.extend(struct.pack("<I", committed_mask))
    buf.extend(struct.pack(f"<{GANA_OPCODES}f", *registers_m))
    for op in committed_ops:
        buf.append(op & 0xFF)
        buf.extend(struct.pack(f"<{GEN4_DIM}f", *vault_c[op]))

    if len(buf) > VALK4_MAX_PACKET_BYTES:
        raise ValueError(f"Composed VALK4 packet {len(buf)} exceeds {VALK4_MAX_PACKET_BYTES} B")
    return bytes(buf)


def _mgs2_basis(vectors: list[list[float]]) -> list[list[float]]:
    basis: list[list[float]] = []
    for raw in vectors:
        v = [float(x) for x in raw]
        for _ in range(2):
            for q in basis:
                dot = sum(vi * qi for vi, qi in zip(v, q))
                v = [vi - dot * qi for vi, qi in zip(v, q)]
        norm = math.sqrt(sum(vi * vi for vi in v))
        if norm > 1e-8:
            basis.append([vi / norm for vi in v])
    return basis


def _project_perp(basis: list[list[float]], cand: list[float]) -> list[float]:
    v = [float(x) for x in cand]
    for _ in range(2):
        for q in basis:
            dot = sum(vi * qi for vi, qi in zip(v, q))
            v = [vi - dot * qi for vi, qi in zip(v, q)]
    return v


def compose_valk4_orthogonal(packet_a: bytes, packet_b: bytes) -> tuple[bytes, dict[str, Any]]:
    """Compose two VALK4 NURESA packets orthogonally (`A +_perp B`) within <= 65,536 B."""
    pa = parse_valk4_packet(packet_a)
    pb = parse_valk4_packet(packet_b)

    committed_a = [pa.vault_c[k] for k in range(GANA_OPCODES) if pa.is_committed(k)]
    basis_a = _mgs2_basis(committed_a)

    merged_c = [[0.0] * GEN4_DIM for _ in range(GANA_OPCODES)]
    merged_m = [0.0] * GANA_OPCODES
    merged_mask = 0
    max_cross_dot = 0.0

    for k in range(GANA_OPCODES):
        ca, cb = pa.is_committed(k), pb.is_committed(k)
        if ca and not cb:
            merged_c[k] = list(pa.vault_c[k])
            merged_m[k] = pa.registers_m[k]
            merged_mask |= 1 << k
        elif not ca and cb:
            perp = _normalize(_project_perp(basis_a, pb.vault_c[k]))
            for va in committed_a:
                max_cross_dot = max(max_cross_dot, abs(sum(x * y for x, y in zip(va, perp))))
            merged_c[k] = perp
            merged_m[k] = pb.registers_m[k]
            merged_mask |= 1 << k
        elif ca and cb:
            merged_c[k] = list(pa.vault_c[k])
            merged_m[k] = max(pa.registers_m[k], pb.registers_m[k])
            merged_mask |= 1 << k

    merged_origin = [0.5 * (a + b) for a, b in zip(pa.origin, pb.origin)]
    onorm = math.sqrt(sum(x * x for x in merged_origin))
    if onorm > 0.90:
        scale = 0.90 / onorm
        merged_origin = [x * scale for x in merged_origin]

    seen: set[bytes] = set()
    engrams: list[tuple[bytes, int]] = []
    for pref, op in pa.engrams + pb.engrams:
        if pref not in seen:
            seen.add(pref)
            engrams.append((pref, op))

    composed = pack_valk4_packet(
        origin=merged_origin,
        vault_c=merged_c,
        registers_m=merged_m,
        committed_mask=merged_mask,
        engrams=engrams,
    )
    meta = {
        "packet_a_bytes": len(packet_a),
        "packet_b_bytes": len(packet_b),
        "composed_bytes": len(composed),
        "within_64k_sram_limit": len(composed) <= VALK4_MAX_PACKET_BYTES,
        "max_subspace_cross_dot": max_cross_dot,
        "committed_mask": merged_mask,
        "engrams_count": len(engrams),
        "sha256_composed": hashlib.sha256(composed).hexdigest(),
    }
    return composed, meta


def seal_and_verify_valk4_in_store(
    store: LocalCrystalStore,
    packet_bytes: bytes,
    *,
    skill_label: str,
) -> dict[str, Any]:
    """Validate VALK4 size/structure, seal in LocalCrystalStore, and verify unsealed roundtrip."""
    parsed = parse_valk4_packet(packet_bytes)
    env = store.append(
        packet_bytes,
        metadata_public={
            "kind": "valk4_nuresa_packet",
            "skill_label": skill_label,
            "packet_bytes": len(packet_bytes),
            "committed_mask": parsed.committed_mask,
            "packet_sha256": parsed.sha256,
        },
    )
    unsealed_list = store.verify_and_unseal()
    if unsealed_list[-1] != packet_bytes:
        raise ValueError("Unsealed crystal payload mismatch")
    return {
        "crystal_id": env["crystal_id"],
        "packet_bytes": len(packet_bytes),
        "packet_sha256": parsed.sha256,
        "within_64k_sram_limit": len(packet_bytes) <= VALK4_MAX_PACKET_BYTES,
    }
