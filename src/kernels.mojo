"""BLAKE2b compression for the Python-facing subset of the ``blake2b`` package.

The package (``blake2b-py``) exposes the EIP-152 precompile primitive: the
compression function F of RFC 7693 with a caller-chosen round count, together
with the decoder for the tightly packed 213-byte precompile input.  That is
pure bit manipulation over 64-bit words, so it ports directly.

Every exported symbol takes buffer addresses as plain ``Int`` values and
rebuilds the pointer inside the body, because ``@export`` rejects parametric
functions.  The 16-word working vector and the decoded parameters live in a
scratch buffer the caller owns, so no kernel allocates.
"""

comptime UPtr = Pointer[UInt64, AnyOrigin[mut=True]]
comptime BPtr = Pointer[UInt8, AnyOrigin[mut=True]]

# RFC 7693 section 2.6
comptime IV0: UInt64 = 0x6a09e667f3bcc908
comptime IV1: UInt64 = 0xbb67ae8584caa73b
comptime IV2: UInt64 = 0x3c6ef372fe94f82b
comptime IV3: UInt64 = 0xa54ff53a5f1d36f1
comptime IV4: UInt64 = 0x510e527fade682d1
comptime IV5: UInt64 = 0x9b05688c2b3e6c1f
comptime IV6: UInt64 = 0x1f83d9abfb41bd6b
comptime IV7: UInt64 = 0x5be0cd19137e2179

comptime ROT1: UInt64 = 32
comptime ROT2: UInt64 = 24
comptime ROT3: UInt64 = 16
comptime ROT4: UInt64 = 63

comptime SCRATCH_WORDS = 44


def up(addr: Int) -> UPtr:
    return UPtr(unsafe_from_address=addr)


def rotr(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))


def g_mix(
    v: UPtr, a: Int, b: Int, c: Int, d: Int, x: UInt64, y: UInt64
) -> None:
    """The BLAKE2b mixing function G, RFC 7693 section 3.1."""
    v[unsafe_offset=a] = v[unsafe_offset=a] + v[unsafe_offset=b] + x
    v[unsafe_offset=d] = rotr(v[unsafe_offset=d] ^ v[unsafe_offset=a], ROT1)
    v[unsafe_offset=c] = v[unsafe_offset=c] + v[unsafe_offset=d]
    v[unsafe_offset=b] = rotr(v[unsafe_offset=b] ^ v[unsafe_offset=c], ROT2)
    v[unsafe_offset=a] = v[unsafe_offset=a] + v[unsafe_offset=b] + y
    v[unsafe_offset=d] = rotr(v[unsafe_offset=d] ^ v[unsafe_offset=a], ROT3)
    v[unsafe_offset=c] = v[unsafe_offset=c] + v[unsafe_offset=d]
    v[unsafe_offset=b] = rotr(v[unsafe_offset=b] ^ v[unsafe_offset=c], ROT4)


def load_le64(p: BPtr, off: Int) -> UInt64:
    """The little-endian 64-bit word at byte offset ``off``."""
    return (
        UInt64(p[unsafe_offset=off])
        | (UInt64(p[unsafe_offset=off + 1]) << 8)
        | (UInt64(p[unsafe_offset=off + 2]) << 16)
        | (UInt64(p[unsafe_offset=off + 3]) << 24)
        | (UInt64(p[unsafe_offset=off + 4]) << 32)
        | (UInt64(p[unsafe_offset=off + 5]) << 40)
        | (UInt64(p[unsafe_offset=off + 6]) << 48)
        | (UInt64(p[unsafe_offset=off + 7]) << 56)
    )


def store_le64(p: BPtr, off: Int, x: UInt64) -> None:
    p[unsafe_offset=off] = UInt8(x & 0xFF)
    p[unsafe_offset=off + 1] = UInt8((x >> 8) & 0xFF)
    p[unsafe_offset=off + 2] = UInt8((x >> 16) & 0xFF)
    p[unsafe_offset=off + 3] = UInt8((x >> 24) & 0xFF)
    p[unsafe_offset=off + 4] = UInt8((x >> 32) & 0xFF)
    p[unsafe_offset=off + 5] = UInt8((x >> 40) & 0xFF)
    p[unsafe_offset=off + 6] = UInt8((x >> 48) & 0xFF)
    p[unsafe_offset=off + 7] = UInt8((x >> 56) & 0xFF)


def b2_compress_core(
    rounds: Int, h_addr: Int, m_addr: Int, t_addr: Int, final_flag: Int,
    v_addr: Int, out_addr: Int
) -> None:
    """The body of F, shared by the compression export and the decoder."""
    var h = up(h_addr)
    var m = up(m_addr)
    var t = up(t_addr)
    var v = up(v_addr)
    var out = BPtr(unsafe_from_address=out_addr)

    for i in range(8):
        v[unsafe_offset=i] = h[unsafe_offset=i]
    v[unsafe_offset=8] = IV0
    v[unsafe_offset=9] = IV1
    v[unsafe_offset=10] = IV2
    v[unsafe_offset=11] = IV3
    v[unsafe_offset=12] = IV4 ^ t[unsafe_offset=0]
    v[unsafe_offset=13] = IV5 ^ t[unsafe_offset=1]
    v[unsafe_offset=14] = IV6
    if final_flag != 0:
        v[unsafe_offset=14] = ~v[unsafe_offset=14]
    v[unsafe_offset=15] = IV7

    for r in range(rounds):
        var s = r % 10
        var s0 = 0
        var s1 = 1
        var s2 = 2
        var s3 = 3
        var s4 = 4
        var s5 = 5
        var s6 = 6
        var s7 = 7
        var s8 = 8
        var s9 = 9
        var s10 = 10
        var s11 = 11
        var s12 = 12
        var s13 = 13
        var s14 = 14
        var s15 = 15
        if s == 1:
            s0 = 14
            s1 = 10
            s2 = 4
            s3 = 8
            s4 = 9
            s5 = 15
            s6 = 13
            s7 = 6
            s8 = 1
            s9 = 12
            s10 = 0
            s11 = 2
            s12 = 11
            s13 = 7
            s14 = 5
            s15 = 3
        elif s == 2:
            s0 = 11
            s1 = 8
            s2 = 12
            s3 = 0
            s4 = 5
            s5 = 2
            s6 = 15
            s7 = 13
            s8 = 10
            s9 = 14
            s10 = 3
            s11 = 6
            s12 = 7
            s13 = 1
            s14 = 9
            s15 = 4
        elif s == 3:
            s0 = 7
            s1 = 9
            s2 = 3
            s3 = 1
            s4 = 13
            s5 = 12
            s6 = 11
            s7 = 14
            s8 = 2
            s9 = 6
            s10 = 5
            s11 = 10
            s12 = 4
            s13 = 0
            s14 = 15
            s15 = 8
        elif s == 4:
            s0 = 9
            s1 = 0
            s2 = 5
            s3 = 7
            s4 = 2
            s5 = 4
            s6 = 10
            s7 = 15
            s8 = 14
            s9 = 1
            s10 = 11
            s11 = 12
            s12 = 6
            s13 = 8
            s14 = 3
            s15 = 13
        elif s == 5:
            s0 = 2
            s1 = 12
            s2 = 6
            s3 = 10
            s4 = 0
            s5 = 11
            s6 = 8
            s7 = 3
            s8 = 4
            s9 = 13
            s10 = 7
            s11 = 5
            s12 = 15
            s13 = 14
            s14 = 1
            s15 = 9
        elif s == 6:
            s0 = 12
            s1 = 5
            s2 = 1
            s3 = 15
            s4 = 14
            s5 = 13
            s6 = 4
            s7 = 10
            s8 = 0
            s9 = 7
            s10 = 6
            s11 = 3
            s12 = 9
            s13 = 2
            s14 = 8
            s15 = 11
        elif s == 7:
            s0 = 13
            s1 = 11
            s2 = 7
            s3 = 14
            s4 = 12
            s5 = 1
            s6 = 3
            s7 = 9
            s8 = 5
            s9 = 0
            s10 = 15
            s11 = 4
            s12 = 8
            s13 = 6
            s14 = 2
            s15 = 10
        elif s == 8:
            s0 = 6
            s1 = 15
            s2 = 14
            s3 = 9
            s4 = 11
            s5 = 3
            s6 = 0
            s7 = 8
            s8 = 12
            s9 = 2
            s10 = 13
            s11 = 7
            s12 = 1
            s13 = 4
            s14 = 10
            s15 = 5
        elif s == 9:
            s0 = 10
            s1 = 2
            s2 = 8
            s3 = 4
            s4 = 7
            s5 = 6
            s6 = 1
            s7 = 5
            s8 = 15
            s9 = 11
            s10 = 9
            s11 = 14
            s12 = 3
            s13 = 12
            s14 = 13
            s15 = 0
        g_mix(v, 0, 4, 8, 12, m[unsafe_offset=s0], m[unsafe_offset=s1])
        g_mix(v, 1, 5, 9, 13, m[unsafe_offset=s2], m[unsafe_offset=s3])
        g_mix(v, 2, 6, 10, 14, m[unsafe_offset=s4], m[unsafe_offset=s5])
        g_mix(v, 3, 7, 11, 15, m[unsafe_offset=s6], m[unsafe_offset=s7])
        g_mix(v, 0, 5, 10, 15, m[unsafe_offset=s8], m[unsafe_offset=s9])
        g_mix(v, 1, 6, 11, 12, m[unsafe_offset=s10], m[unsafe_offset=s11])
        g_mix(v, 2, 7, 8, 13, m[unsafe_offset=s12], m[unsafe_offset=s13])
        g_mix(v, 3, 4, 9, 14, m[unsafe_offset=s14], m[unsafe_offset=s15])

    for i in range(8):
        store_le64(
            out,
            8 * i,
            h[unsafe_offset=i] ^ v[unsafe_offset=i] ^ v[unsafe_offset=i + 8],
        )


@export("b2_compress")
def b2_compress(
    rounds: Int, h_addr: Int, m_addr: Int, t_addr: Int, final_flag: Int,
    v_addr: Int, out_addr: Int
) abi("C") -> None:
    """The BLAKE2b compression function F, as the package exposes it.

    ``h_addr`` is 8 words, ``m_addr`` 16 words, ``t_addr`` 2 words, ``v_addr``
    16 words of scratch, and 64 bytes are written to ``out_addr``.
    """
    b2_compress_core(rounds, h_addr, m_addr, t_addr, final_flag, v_addr, out_addr)


@export("b2_compress_stream")
def b2_compress_stream(
    rounds: Int, h_addr: Int, m_addr: Int, t_addr: Int, data_addr: Int,
    nblocks: Int, v_addr: Int
) abi("C") -> None:
    """Compress ``nblocks`` whole 128-byte blocks in one call.

    The running counter at ``t_addr`` is advanced by 128 per block and the
    chaining value at ``h_addr`` is updated in place, so a megabyte costs one
    cross into the library instead of one per block.  The final block is left
    to the caller, because it needs the total length and the finalisation flag.
    """
    var h = up(h_addr)
    var m = up(m_addr)
    var t = up(t_addr)
    var v = up(v_addr)
    var src = BPtr(unsafe_from_address=data_addr)
    var hbuf = BPtr(unsafe_from_address=h_addr)
    var tbuf = BPtr(unsafe_from_address=t_addr)
    var total = t[unsafe_offset=0]
    for b in range(nblocks):
        for i in range(16):
            m[unsafe_offset=i] = load_le64(src, 128 * b + 8 * i)
        total = total + 128
        store_le64(tbuf, 0, total)
        b2_compress_core(rounds, h_addr, m_addr, t_addr, 0, v_addr, h_addr)
    return


@export("b2_decode_parameters")
def b2_decode_parameters(
    input_addr: Int, input_len: Int, scratch_addr: Int
) abi("C") -> Int:
    """Decode the EIP-152 tightly packed precompile input into ``scratch_addr``.

    The scratch buffer is 44 little-endian words: ``h`` at 0..7, ``m`` at 8..23,
    ``t`` at 24..25, the 16-word working vector at 26..41, the round count at
    42 and the final-block flag at 43.  Returns 0 on success, 1 for a wrong
    input length and 2 for a final-block flag that is neither 0 nor 1; the
    caller turns those into the package's ValueErrors.
    """
    if input_len != 213:
        return 1
    var src = BPtr(unsafe_from_address=input_addr)
    var flag = Int(src[unsafe_offset=212])
    if flag != 0 and flag != 1:
        return 2
    var sc = up(scratch_addr)
    var rounds = (
        Int(src[unsafe_offset=0]) << 24
        | (Int(src[unsafe_offset=1]) << 16)
        | (Int(src[unsafe_offset=2]) << 8)
        | Int(src[unsafe_offset=3])
    )
    for i in range(8):
        sc[unsafe_offset=i] = load_le64(src, 4 + 8 * i)
    for i in range(16):
        sc[unsafe_offset=8 + i] = load_le64(src, 68 + 8 * i)
    sc[unsafe_offset=24] = load_le64(src, 196)
    sc[unsafe_offset=25] = load_le64(src, 204)
    sc[unsafe_offset=42] = UInt64(rounds)
    sc[unsafe_offset=43] = UInt64(flag)
    return 0


@export("b2_decode_and_compress")
def b2_decode_and_compress(
    input_addr: Int, input_len: Int, scratch_addr: Int, out_addr: Int
) abi("C") -> Int:
    """Decode the packed precompile input and run one compression over it.

    Same scratch layout as ``b2_decode_parameters`` with the working vector
    reused, so the whole EIP-152 path is one call and no allocation.
    """
    var status = b2_decode_parameters(input_addr, input_len, scratch_addr)
    if status != 0:
        return status
    var sc = up(scratch_addr)
    b2_compress_core(
        Int(sc[unsafe_offset=42]),
        scratch_addr,
        scratch_addr + 8 * 8,
        scratch_addr + 24 * 8,
        Int(sc[unsafe_offset=43]),
        scratch_addr + 26 * 8,
        out_addr,
    )
    return 0
