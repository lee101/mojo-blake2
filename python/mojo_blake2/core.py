"""BLAKE2b: the EIP-152 precompile primitive, plus a digest built on it.

``compress``, ``decode_parameters`` and ``decode_and_compress`` have exactly
the signatures and error behaviour of the ``blake2b`` package (blake2b-py
0.4.0), so code written against that package runs unchanged.

``Blake2b`` / ``blake2b`` are an addition: a standard RFC 7693 digest
assembled from the same compression kernel.  It is what makes the port
checkable against ``hashlib.blake2b``, which is the authority for the
standard rather than for EIP-152.
"""

from __future__ import annotations

import numpy as np

from . import _lib

__all__ = [
    "compress",
    "decode_parameters",
    "decode_and_compress",
    "Blake2b",
    "blake2b",
    "BLOCK_SIZE",
]

BLOCK_SIZE = 128
OUT_SIZE = 64

IV = np.array(
    [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ],
    dtype=np.uint64,
)

_BAD_LEN = (
    "input length for blake2 F precompile should be exactly 213 bytes, got: {}"
)
_BAD_FLAG = "incorrect final block indicator flag, got: {}"


def _words(values) -> np.ndarray:
    return np.ascontiguousarray(values, dtype=np.uint64)


def _as_bytes(data) -> bytes:
    return bytes(data)


def compress(
    rounds, starting_state, block, offset_counters, final_block_flag
) -> bytes:
    """The BLAKE2b compression function F (RFC 7693 section 3.2).

    ``starting_state`` is 8 64-bit words, ``block`` is 16, ``offset_counters``
    is 2, and the result is the 64-byte little-endian finalisation.
    """
    h = _words(starting_state)
    if h.size != 8:
        raise ValueError("starting_state must have exactly 8 words")
    m = _words(block)
    if m.size != 16:
        raise ValueError("block must have exactly 16 words")
    t = _words(offset_counters)
    if t.size != 2:
        raise ValueError("offset_counters must have exactly 2 words")
    v = _lib.scratch()
    out = np.zeros(OUT_SIZE, dtype=np.uint8)
    _lib.lib.b2_compress(
        int(rounds),
        _lib.addr(h),
        _lib.addr(m),
        _lib.addr(t),
        int(final_block_flag),
        _lib.addr(v),
        _lib.addr(out),
    )
    return out.tobytes()


def decode_parameters(data):
    """Decode the EIP-152 tightly packed precompile input.

    Returns ``(rounds, starting_state, block, offset_counters, flag)``.
    """
    raw = _as_bytes(data)
    sc = _lib.scratch()
    buf = np.frombuffer(raw + b"\0" * 213, dtype=np.uint8, count=213)
    status = _lib.lib.b2_decode_parameters(
        _lib.addr(buf), len(raw), _lib.addr(sc)
    )
    _raise_status(status, len(raw), raw)
    return (
        int(sc[42]),
        sc[0:8].copy(),
        sc[8:24].copy(),
        sc[24:26].copy(),
        bool(int(sc[43])),
    )


def decode_and_compress(data) -> bytes:
    """Decode the packed precompile input and run one compression over it."""
    raw = _as_bytes(data)
    sc = _lib.scratch()
    out = np.zeros(OUT_SIZE, dtype=np.uint8)
    buf = np.frombuffer(raw + b"\0" * 213, dtype=np.uint8, count=213)
    status = _lib.lib.b2_decode_and_compress(
        _lib.addr(buf), len(raw), _lib.addr(sc), _lib.addr(out)
    )
    _raise_status(status, len(raw), raw)
    return out.tobytes()


def _raise_status(status: int, length: int, raw: bytes) -> None:
    if status == 1:
        raise ValueError(_BAD_LEN.format(length))
    if status == 2:
        flag = raw[212] if len(raw) == 213 else -1
        raise ValueError(_BAD_FLAG.format(flag))


class Blake2b:
    """RFC 7693 BLAKE2b, one compression kernel call per 128-byte block.

    The streaming rule is the standard one: a block is compressed only once it
    is known that more data follows, so the last block is always the one that
    carries the finalisation flag and the total length.
    """

    __slots__ = ("_h", "_buf", "_count", "_v", "_m", "_t", "_digest_size")

    def __init__(
        self,
        data: bytes = b"",
        *,
        digest_size: int = OUT_SIZE,
        key: bytes = b"",
        salt: bytes = b"",
        person: bytes = b"",
    ) -> None:
        if digest_size != OUT_SIZE:
            # RFC 7693 defines the 64-byte digest; a shorter one is the
            # BLAKE2X truncated-node mode, which this port does not implement
            raise ValueError(
                "digest_size must be 64: the short-digest XOF mode is not "
                "implemented"
            )
        if len(key) > 64:
            raise ValueError("key must be at most 64 bytes")
        if len(salt) > 16 or len(person) > 16:
            raise ValueError("salt and person must be at most 16 bytes")
        self._digest_size = digest_size
        self._h = IV.copy()
        # parameter block: digest length, key length, fanout 1, depth 1
        self._h[0] = np.uint64(
            int(self._h[0]) ^ 0x01010000 ^ (len(key) << 8) ^ digest_size
        )
        if key:
            # the key is a 128-byte message block, not a parameter block
            pass
        if salt:
            self._h[4] ^= np.uint64(int.from_bytes(salt[:8].ljust(8, b"\0"), "little"))
            self._h[5] ^= np.uint64(
                int.from_bytes(salt[8:16].ljust(8, b"\0"), "little")
            )
        if person:
            self._h[6] ^= np.uint64(
                int.from_bytes(person[:8].ljust(8, b"\0"), "little")
            )
            self._h[7] ^= np.uint64(
                int.from_bytes(person[8:16].ljust(8, b"\0"), "little")
            )
        self._v = _lib.scratch()
        self._m = _lib.blocks()
        self._t = np.zeros(2, dtype=np.uint64)
        self._buf = bytearray()
        self._count = 0
        if key:
            self.update(key.ljust(BLOCK_SIZE, b"\0"))
        if data:
            self.update(data)

    def _compress(self, block: bytes, total: int, final: int) -> None:
        t_words = np.array(
            [total & 0xFFFFFFFFFFFFFFFF, (total >> 64) & 0xFFFFFFFFFFFFFFFF],
            dtype=np.uint64,
        )
        m = np.frombuffer(block, dtype="<u8")
        out = np.zeros(OUT_SIZE, dtype=np.uint8)
        _lib.lib.b2_compress(
            12,
            _lib.addr(self._h),
            _lib.addr(m),
            _lib.addr(t_words),
            final,
            _lib.addr(self._v),
            _lib.addr(out),
        )
        self._h = np.frombuffer(out.tobytes(), dtype="<u8").copy()

    def update(self, data: bytes) -> "Blake2b":
        """Blocks are compressed in one kernel call per update, not per block:
        the counter and chaining value are advanced inside the library."""
        self._buf += _as_bytes(data)
        # keep the last block: it is the one that gets finalised
        whole = max(0, (len(self._buf) - 1) // BLOCK_SIZE)
        if whole:
            take = whole * BLOCK_SIZE
            block = bytes(self._buf[:take])
            del self._buf[:take]
            # the kernel advances the counter itself, so seed it with the count
            # before this batch
            self._t[0] = np.uint64(self._count & 0xFFFFFFFFFFFFFFFF)
            self._t[1] = np.uint64((self._count >> 64) & 0xFFFFFFFFFFFFFFFF)
            self._count += take
            raw = np.frombuffer(block, dtype=np.uint8)
            _lib.lib.b2_compress_stream(
                12,
                _lib.addr(self._h),
                _lib.addr(self._m),
                _lib.addr(self._t),
                _lib.addr(raw),
                whole,
                _lib.addr(self._v),
            )
            self._h = np.frombuffer(self._h.tobytes(), dtype="<u8").copy()
        return self

    def digest(self) -> bytes:
        """Non-destructive: the streaming state is untouched, so a digest can be
        taken mid-stream and more data appended afterwards."""
        tail = bytes(self._buf)
        total = self._count + len(tail)
        h = self._h.copy()
        v = self._v
        t_words = np.array([total & 0xFFFFFFFFFFFFFFFF, 0], dtype=np.uint64)
        m = np.frombuffer(tail.ljust(BLOCK_SIZE, b"\0"), dtype="<u8")
        out = np.zeros(OUT_SIZE, dtype=np.uint8)
        _lib.lib.b2_compress(
            12, _lib.addr(h), _lib.addr(m), _lib.addr(t_words), 1,
            _lib.addr(v), _lib.addr(out),
        )
        return out.tobytes()[: self._digest_size]

    def hexdigest(self) -> str:
        return self.digest().hex()


def blake2b(
    data: bytes = b"",
    *,
    digest_size: int = OUT_SIZE,
    key: bytes = b"",
    salt: bytes = b"",
    person: bytes = b"",
) -> bytes:
    return Blake2b(
        data,
        digest_size=digest_size,
        key=key,
        salt=salt,
        person=person,
    ).digest()
