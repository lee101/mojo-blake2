"""Correctness-gated benchmark for mojo-blake2.

Every case checks the Mojo result against an independent source before
timing: the pure-Python transcription of RFC 7693 in ``tests/reference.py`` for
the compression function, and ``hashlib.blake2b`` for the streaming digest.
A kernel regression shows up as a correctness failure, not as a good number.
"""

from __future__ import annotations

import hashlib
import pathlib
import random
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "python"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests"))

import mojo_blake2 as mb  # noqa: E402
import reference as ref  # noqa: E402


def _time(fn, repeats=3):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_compress(rounds: int = 12, calls: int = 2000):
    """One EIP-152 compression against the Python transcription of F."""
    rng = random.Random(1)
    h = [rng.getrandbits(64) for _ in range(8)]
    m = [rng.getrandbits(64) for _ in range(16)]
    t = [rng.getrandbits(64), rng.getrandbits(64)]
    assert mb.compress(rounds, h, m, t, 1) == ref.compress(rounds, h, m, t, 1)

    def run_mine():
        for _ in range(calls):
            mb.compress(rounds, h, m, t, 1)

    def run_ref():
        for _ in range(calls):
            ref.compress(rounds, h, m, t, 1)

    return f"compress rounds={rounds} x{calls}", _time(run_ref, 1), _time(run_mine)


def bench_decode_and_compress(calls: int = 2000):
    """The full EIP-152 path: 213-byte decode plus one compression."""
    rng = random.Random(2)
    h = [rng.getrandbits(64) for _ in range(8)]
    m = [rng.getrandbits(64) for _ in range(16)]
    t = [rng.getrandbits(64), rng.getrandbits(64)]
    raw = (
        (12).to_bytes(4, "big")
        + b"".join(x.to_bytes(8, "little") for x in h)
        + b"".join(x.to_bytes(8, "little") for x in m)
        + b"".join(x.to_bytes(8, "little") for x in t)
        + b"\x01"
    )
    assert len(raw) == 213
    assert mb.decode_and_compress(raw) == ref.compress(12, h, m, t, 1)
    rounds, dh, dm, dt, flag = ref.decode_parameters(raw)

    def run_mine():
        for _ in range(calls):
            mb.decode_and_compress(raw)

    def run_ref():
        for _ in range(calls):
            ref.decode_parameters(raw)
            ref.compress(rounds, dh, dm, dt, flag)

    return f"decode+compress x{calls}", _time(run_ref, 1), _time(run_mine)


def bench_digest(n: int = 1 << 20):
    """Whole-message throughput against hashlib, the fastest fair baseline."""
    rng = random.Random(3)
    data = bytes(rng.randrange(256) for _ in range(n))
    assert mb.blake2b(data) == hashlib.blake2b(data).digest()
    return (
        f"digest {n} bytes",
        _time(lambda: hashlib.blake2b(data).digest()),
        _time(lambda: mb.blake2b(data)),
    )


def bench_digest_small(n: int = 64, calls: int = 20000):
    """A one-block message: the per-call overhead, not the throughput."""
    rng = random.Random(4)
    data = bytes(rng.randrange(256) for _ in range(n))
    assert mb.blake2b(data) == hashlib.blake2b(data).digest()

    def run_mine():
        for _ in range(calls):
            mb.blake2b(data)

    def run_theirs():
        for _ in range(calls):
            hashlib.blake2b(data).digest()

    return f"digest {n} bytes x{calls}", _time(run_theirs, 1), _time(run_mine)


CASES = (bench_compress, bench_decode_and_compress, bench_digest, bench_digest_small)


def main():
    print(f"{'case':<30}{'reference':>12}{'mojo-blake2':>14}{'ratio':>10}")
    print("-" * 66)
    for fn in CASES:
        label, base, got = fn()
        print(f"{label:<30}{base*1e3:>10.2f}ms{got*1e3:>12.3f}ms{base/got:>9.1f}x")


if __name__ == "__main__":
    main()
