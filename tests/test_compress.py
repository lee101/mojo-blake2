"""The compression function against a pure-Python transcription of RFC 7693."""

import random

import pytest

import mojo_blake2 as mb
import reference as ref


def words(rng, count, top=None):
    return [rng.getrandbits(64) for _ in range(count)]


@pytest.mark.parametrize("rounds", [0, 1, 2, 5, 10, 11, 12, 13, 17, 20, 64, 130])
def test_compress_matches_reference_for_any_round_count(rounds):
    rng = random.Random(1000 + rounds)
    for _ in range(6):
        h = words(rng, 8)
        m = words(rng, 16)
        t = [rng.getrandbits(64), rng.getrandbits(64)]
        for flag in (0, 1):
            got = mb.compress(rounds, h, m, t, flag)
            assert got == ref.compress(rounds, h, m, t, flag), (rounds, flag)


def test_compress_is_not_symmetric_in_the_final_flag():
    """The finalisation flag flips every bit of v[14], so a kernel that drops it
    produces the same digest for a truncated and a complete message."""
    rng = random.Random(2000)
    h, m, t = words(rng, 8), words(rng, 16), [rng.getrandbits(64), 0]
    assert mb.compress(12, h, m, t, 0) != mb.compress(12, h, m, t, 1)


def test_offset_counters_are_xored_into_v12_and_v13():
    rng = random.Random(2001)
    h, m = words(rng, 8), words(rng, 16)
    a = mb.compress(12, h, m, [0, 0], 1)
    b = mb.compress(12, h, m, [1, 0], 1)
    c = mb.compress(12, h, m, [0, 1], 1)
    assert len({a, b, c}) == 3


def test_compress_rejects_wrong_shapes():
    with pytest.raises(ValueError):
        mb.compress(12, [0] * 7, [0] * 16, [0, 0], 0)
    with pytest.raises(ValueError):
        mb.compress(12, [0] * 8, [0] * 15, [0, 0], 0)
    with pytest.raises(ValueError):
        mb.compress(12, [0] * 8, [0] * 16, [0], 0)


def test_zero_rounds_is_the_finalisation_alone():
    """With no rounds, v is just h concatenated with the IV, so the
    finalisation h ^ v ^ v[i+8] cancels h and leaves the IV (with the counter
    and flag mixed into words 12 and 14).  A kernel that ran a round anyway
    would not produce this."""
    h = [0x0123456789ABCDEF] * 8
    iv = list(ref.IV)
    iv[4] ^= 0  # t0
    expect = b"".join(x.to_bytes(8, "little") for x in iv)
    assert mb.compress(0, h, [0] * 16, [0, 0], 0) == expect
    flagged = list(iv)
    flagged[6] ^= ref.MASK
    assert mb.compress(0, h, [0] * 16, [0, 0], 1) == b"".join(
        x.to_bytes(8, "little") for x in flagged
    )


def test_known_answer_against_hashlib_block():
    """One BLAKE2b block of the digest of b"abc", the canonical vector."""
    import hashlib

    h = ref.initial_state()
    block = b"abc".ljust(128, b"\0")
    got = mb.compress(12, h, [int.from_bytes(block[8 * i : 8 * i + 8], "little")
                              for i in range(16)], [3, 0], 1)
    assert got == hashlib.blake2b(b"abc").digest()
