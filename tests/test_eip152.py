"""EIP-152 precompile parity: the package's own vectors, decoded and compressed.

Every vector here comes from the upstream package's ``test()`` function, so
this is a check against the published EIP-152 test values rather than against
anything this port believes.
"""

import binascii

import pytest

import mojo_blake2 as mb
import reference as ref
from conftest import VECTORS, needs_vectors


@needs_vectors
@pytest.mark.parametrize("raw,expected", VECTORS.get("FAST_EXAMPLES", []))
def test_fast_eip152_vectors(raw, expected):
    got = binascii.hexlify(mb.decode_and_compress(binascii.unhexlify(raw)))
    assert got.decode() == expected


@needs_vectors
@pytest.mark.parametrize("raw,expected", VECTORS.get("SLOW_EXAMPLES", []))
def test_slow_eip152_vectors(raw, expected):
    """Two million and eight million rounds: the sigma chain is indexed by
    ``round % 10``, so only a long run exercises every row several times."""
    got = binascii.hexlify(mb.decode_and_compress(binascii.unhexlify(raw)))
    assert got.decode() == expected


@needs_vectors
@pytest.mark.parametrize("raw", VECTORS.get("ERROR_EXAMPLES", []))
def test_error_inputs_raise_value_error(raw):
    data = binascii.unhexlify(raw)
    with pytest.raises(ValueError):
        mb.decode_parameters(data)
    with pytest.raises(ValueError):
        mb.decode_and_compress(data)


@needs_vectors
def test_error_messages_match_the_package():
    with pytest.raises(ValueError) as exc:
        mb.decode_parameters(b"")
    assert str(exc.value) == (
        "input length for blake2 F precompile should be exactly 213 bytes, got: 0"
    )
    bad = bytearray(b"\0" * 213)
    bad[212] = 2
    with pytest.raises(ValueError) as exc:
        mb.decode_parameters(bytes(bad))
    assert str(exc.value) == "incorrect final block indicator flag, got: 2"


@needs_vectors
def test_decode_parameters_round_trip():
    for raw, _ in VECTORS.get("FAST_EXAMPLES", []):
        data = binascii.unhexlify(raw)
        rounds, h, m, t, flag = mb.decode_parameters(data)
        want = ref.decode_parameters(data)
        assert rounds == want[0]
        assert list(map(int, h)) == want[1]
        assert list(map(int, m)) == want[2]
        assert list(map(int, t)) == want[3]
        assert flag == bool(want[4])


def test_decode_parameters_is_big_endian_for_rounds():
    """The round count is the one big-endian field in the packed input; a
    little-endian read would turn 12 into 0x0c000000."""
    raw = bytearray(b"\0" * 213)
    raw[0:4] = (12).to_bytes(4, "big")
    rounds, _, _, _, _ = mb.decode_parameters(bytes(raw))
    assert rounds == 12
    raw[0:4] = (0x01020304).to_bytes(4, "big")
    assert mb.decode_parameters(bytes(raw))[0] == 0x01020304
