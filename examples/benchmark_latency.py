#!/usr/bin/env python3
"""Benchmark local seal and unseal performance of whitemagic-crystal."""

import time
import statistics
from whitemagic_crystal import CrystalClient, generate_key


def benchmark_cipher(cipher_name: str, payload_size_bytes: int = 1024, iterations: int = 1000):
    client = CrystalClient(tenant_id="bench-agent", cipher=cipher_name, ephemeral=True)
    payload = "A" * payload_size_bytes

    # Seal benchmark
    seal_latencies = []
    envelopes = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        env = client.seal(payload)
        t1 = time.perf_counter_ns()
        seal_latencies.append((t1 - t0) / 1000.0) # µs
        envelopes.append(env)

    # Unseal benchmark
    unseal_latencies = []
    for env in envelopes:
        t0 = time.perf_counter_ns()
        _ = client.unseal(env)
        t1 = time.perf_counter_ns()
        unseal_latencies.append((t1 - t0) / 1000.0) # µs

    seal_median = statistics.median(seal_latencies)
    seal_p99 = statistics.quantiles(seal_latencies, n=100)[98]
    unseal_median = statistics.median(unseal_latencies)
    unseal_p99 = statistics.quantiles(unseal_latencies, n=100)[98]

    throughput_seal = iterations / (sum(seal_latencies) / 1_000_000.0)
    throughput_unseal = iterations / (sum(unseal_latencies) / 1_000_000.0)

    print(f"\n--- {cipher_name} ({payload_size_bytes} bytes, {iterations} ops) ---")
    print(f"  Seal   Median: {seal_median:.2f} µs | P99: {seal_p99:.2f} µs | Throughput: {throughput_seal:,.0f} ops/sec")
    print(f"  Unseal Median: {unseal_median:.2f} µs | P99: {unseal_p99:.2f} µs | Throughput: {throughput_unseal:,.0f} ops/sec")


def main():
    print("==================================================")
    print(" WhiteMagic Memory Crystal Microbenchmark")
    print(" Client-side Authenticated Encryption (AEAD)")
    print("==================================================")
    for size in [256, 1024, 8192]:
        benchmark_cipher("AES-256-GCM", payload_size_bytes=size, iterations=1000)
        benchmark_cipher("ChaCha20-Poly1305", payload_size_bytes=size, iterations=1000)


if __name__ == "__main__":
    main()
