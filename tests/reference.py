"""A reference BLAKE2b compression function in plain Python.

Transcribed from RFC 7693 sections 3.1 and 3.2.  It shares no code with the
Mojo kernel, so comparing the two catches a wrong rotation constant, a
transposed G index, a bad sigma row or a mis-stored finalisation word.  The
slow vectors in the package's own test suite make this unnecessary for the
standard round count, but it covers arbitrary round counts, which EIP-152
allows and the standard never uses.
"""

from __future__ import annotations

MASK = 0xFFFFFFFFFFFFFFFF

IV = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]

SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

BLOCK_SIZE = 128
OUT_SIZE = 64


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK


def compress(rounds: int, h, m, t, final_flag: int) -> bytes:
    v = list(h) + IV[:]
    v[12] ^= t[0]
    v[13] ^= t[1]
    v[14] ^= MASK if final_flag else 0
    for r in range(rounds):
        s = SIGMA[r % 10]
        v = _mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
        v = _mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
        v = _mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        v = _mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        v = _mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        v = _mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        v = _mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
        v = _mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
    return b"".join(
        ((h[i] ^ v[i] ^ v[i + 8]) & MASK).to_bytes(8, "little") for i in range(8)
    )


def _mix(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK
    v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + y) & MASK
    v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotr(v[b] ^ v[c], 63)
    return v


def decode_parameters(raw: bytes):
    """The EIP-152 packed input layout, independently decoded."""
    if len(raw) != 213:
        raise ValueError(len(raw))
    rounds = int.from_bytes(raw[0:4], "big")
    h = [int.from_bytes(raw[4 + 8 * i : 12 + 8 * i], "little") for i in range(8)]
    m = [int.from_bytes(raw[68 + 8 * i : 76 + 8 * i], "little") for i in range(16)]
    t = [
        int.from_bytes(raw[196:204], "little"),
        int.from_bytes(raw[204:212], "little"),
    ]
    flag = raw[212]
    if flag > 1:
        raise ValueError(flag)
    return rounds, h, m, t, flag


def initial_state(digest_size: int = 64, key: bytes = b"") -> list:
    h = list(IV)
    h[0] ^= 0x01010000 ^ (len(key) << 8) ^ digest_size
    if key:
        block = key.ljust(BLOCK_SIZE, b"\0")
        words = [
            int.from_bytes(block[8 * i : 8 * i + 8], "little") for i in range(16)
        ]
        h = [a ^ b for a, b in zip(h, words)]
    return h
