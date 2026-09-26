"""The RFC 7693 digest built on the compression kernel, against hashlib."""

import hashlib
import random

import pytest

import mojo_blake2 as mb


@pytest.mark.parametrize(
    "n", [0, 1, 2, 63, 64, 127, 128, 129, 255, 256, 257, 1000, 4096, 10000]
)
def test_digest_matches_hashlib(n):
    data = bytes((i * 37 + n) % 256 for i in range(n))
    assert mb.blake2b(data) == hashlib.blake2b(data).digest()


def test_empty_matches_the_published_digest():
    assert (
        mb.blake2b(b"").hex()
        == hashlib.blake2b(b"").hexdigest()
        == (
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        )
    )
    assert mb.blake2b(b"abc") == hashlib.blake2b(b"abc").digest()


@pytest.mark.parametrize("key_len", [0, 1, 16, 32, 64])
def test_keyed_digest_matches_hashlib(key_len):
    key = bytes(range(key_len))
    data = b"the quick brown fox jumps over the lazy dog" * 5
    assert mb.blake2b(data, key=key) == hashlib.blake2b(data, key=key).digest()


def test_salt_and_person_match_hashlib():
    data = b"salted and personalised"
    assert mb.blake2b(data, salt=b"\x01" * 16) == hashlib.blake2b(
        data, salt=b"\x01" * 16
    ).digest()
    assert mb.blake2b(data, person=b"person") == hashlib.blake2b(
        data, person=b"person"
    ).digest()
    assert mb.blake2b(
        data, key=b"k" * 8, salt=b"s" * 16, person=b"p" * 16
    ) == hashlib.blake2b(
        data, key=b"k" * 8, salt=b"s" * 16, person=b"p" * 16
    ).digest()


def test_chunked_updates_match_a_single_update():
    rng = random.Random(7)
    data = bytes(rng.randrange(256) for _ in range(5000))
    one = mb.blake2b(data)
    for chunk in (1, 7, 64, 128, 129, 1000):
        h = mb.Blake2b()
        for i in range(0, len(data), chunk):
            h.update(data[i : i + chunk])
        assert h.digest() == one, chunk


def test_digest_does_not_consume_the_stream():
    h = mb.Blake2b(b"abc")
    first = h.digest()
    assert h.digest() == first
    h.update(b"abc")
    assert h.digest() == mb.blake2b(b"abcabc")


def test_parameter_validation():
    with pytest.raises(ValueError):
        mb.blake2b(b"", digest_size=0)
    with pytest.raises(ValueError):
        mb.blake2b(b"", digest_size=65)
    with pytest.raises(ValueError):
        mb.blake2b(b"", digest_size=32)
    with pytest.raises(ValueError):
        mb.blake2b(b"", key=b"k" * 65)
    with pytest.raises(ValueError):
        mb.blake2b(b"", salt=b"s" * 17)
    with pytest.raises(ValueError):
        mb.blake2b(b"", person=b"p" * 17)


def test_a_64_byte_block_boundary_matters():
    """A message that is exactly one block long must be finalised as the last
    block, not compressed twice."""
    one_block = b"a" * 128
    assert mb.blake2b(one_block) == hashlib.blake2b(one_block).digest()
    two_blocks = b"a" * 256
    assert mb.blake2b(two_blocks) == hashlib.blake2b(two_blocks).digest()
    assert mb.blake2b(one_block) != mb.blake2b(two_blocks)[:64]
