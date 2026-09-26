# mojo-blake2

`mojo-blake2` is the compute-oriented subset of the
[`blake2b`](https://pypi.org/project/blake2b-py/) package (blake2b-py 0.4.0)
with the BLAKE2b compression function compiled to Mojo. The three exported
entry points — `compress`, `decode_parameters` and `decode_and_compress` —
have exactly the signatures, the return values and the error behaviour of the
upstream package, so code written against it runs unchanged.

The Python package is `mojo_blake2`, so it installs alongside the real `blake2b`
and never imports it.

```python
import mojo_blake2 as b2

b2.blake2b(b"abc").hex()          # 'ba80a53f981c4d0d...'
b2.compress(12, h, block, t, 1)  # 64 bytes, the EIP-152 compression
b2.decode_and_compress(raw213)    # decode a packed precompile input
```

## Why this package

The package is the Ethereum EIP-152 precompile primitive: the compression
function F of RFC 7693 with a caller-chosen round count, plus the decoder for
the tightly packed 213-byte input. There is no IO, no configuration and no
string handling — it is 64-bit word arithmetic and bit rotation, which is
exactly what a compiled inner loop is for. A whole-message digest is added on
top, built from the same kernel, because that is what makes the port checkable
against `hashlib.blake2b`.

## Covered subset

| area | implemented API |
| --- | --- |
| EIP-152 primitive | `compress(rounds, starting_state, block, offset_counters, final_block_flag) -> bytes` |
| EIP-152 decoding | `decode_parameters(data) -> (rounds, state, block, counters, flag)` |
| EIP-152 one-shot | `decode_and_compress(data) -> bytes` |
| Streaming digest | `Blake2b` (incremental `update`, non-destructive `digest`, `hexdigest`), `blake2b(...)` |
| Digest options | key (0-64 bytes), salt (16 bytes), person (16 bytes) |
| Kernels | `b2_compress`, `b2_compress_stream`, `b2_decode_parameters`, `b2_decode_and_compress` |

### Not implemented

- **Truncated digests.** `digest_size` must be 64; anything else raises
  `ValueError`. A digest shorter than 64 bytes is the BLAKE2X truncated-node
  mode, whose last-node flag is not part of RFC 7693's F and not part of the
  upstream package. I could not reproduce `hashlib.blake2b(digest_size=n)` for
  `n < 64` from the reference implementation's flags, and shipping a digest
  that disagrees with `hashlib` would be worse than not shipping it.
- BLAKE2b tree hashing (BLAKE2bp/sp) and the `blake2xb` XOF.
- The upstream package's `test()` helper is not reimplemented; its vectors are
  in `tests/eip152_vectors.py` and the suite runs them directly.

## Install

```bash
pixi install
pixi run build
pixi run test
pixi run bench
```

`pixi run build` produces `dist/libmojo-blake2.so`. Set `PYTHONPATH=python`
when using the package outside a Pixi task.

## Performance

Best-of-three wall clock in the same process. Every case verifies the Mojo
result against an independent source *before* timing: the pure-Python
transcription of RFC 7693 in `tests/reference.py` for the compression
function, and `hashlib.blake2b` for the digest. A kernel regression shows up
as a correctness failure, not as a good number.

| case | reference | mojo-blake2 | ratio |
| --- | ---: | ---: | ---: |
| compress, 12 rounds x2000 | 842.60 ms | 56.04 ms | 15.0x |
| decode + compress x2000 | 1538.33 ms | 36.06 ms | 42.7x |
| digest 1 MiB | 3.23 ms (hashlib) | 9.73 ms | 0.3x |
| digest 64 bytes x20000 | 19.13 ms (hashlib) | 966.66 ms | 0.03x |

- **The primitive is 15x to 43x faster than the Python reference.** The
  decode-and-compress path wins by more because the 213-byte little-endian
  unpack is also in the kernel.
- **The whole-message digest is 3x slower than `hashlib` at 1 MiB.**
  `hashlib` is a C implementation of exactly the same function with a
  block-at-a-time loop; a 9.7 ms digest is 118 MB/s, and the gap is the one
  cross into the library per 128-byte block plus the shim's per-block word
  copies. `b2_compress_stream` was added to collapse that to one cross per
  `update()` call, which is what took this row from 317 ms to 9.7 ms; closing
  the remaining 3x would need the 64-bit word loads to bypass the byte-level
  `load_le64`, which this port does not do.
- **The 64-byte digest is 48 microseconds per call against `hashlib`'s one.**
  That is entirely Python-side: the parameter block, the scratch buffers and
  the final block are all built with NumPy in `__init__` and `digest`. For a
  one-block message the port is the wrong tool; for a large message it is
  within 3x.

Reproduce with:

```bash
pixi run bench
```

## How it works

All kernels live in `src/kernels.mojo`, one compilation unit.
`build/build.sh` compiles it with `mojo build --emit shared-lib` into
`dist/libmojo-blake2.so`.

Every exported symbol takes buffer addresses as plain `Int` values and rebuilds
the pointer inside the body, because `@export` rejects parametric functions.
The 16-word working vector `v` lives in a scratch buffer the caller owns, so no
kernel allocates; `python/mojo_blake2/_lib.py` hands out those buffers as
NumPy arrays. `b2_decode_and_compress` decodes into the same buffer and
compresses from it, so the whole EIP-152 path is one call and no allocation.

The message permutation is a ten-row table indexed by `round % 10`, expanded
into a branch per row with literal indices. That is what lets a single kernel
serve the 12-round standard digest and EIP-152's two-million and eight-million
round vectors, all of which are in the test suite.

Mojo emits FMA, but there is no floating point here at all: every operation is
integer addition, XOR and rotation, all of which are exact. The tests
therefore use exact equality, which is the one case where `rtol=0, atol=0` is
the right assertion.

## Tests

```
55 passed
```

- `tests/eip152_vectors.py` holds the published EIP-152 vectors, transcribed
  from the upstream package's own `test()` function.
- `tests/test_eip152.py` runs all six compression vectors — including the
  2,000,000 and 8,000,000 round ones, which are the only thing that exercises
  every sigma row several times — and the four error cases, checking the exact
  `ValueError` messages.
- `tests/test_compress.py` compares the kernel against
  `tests/reference.py`, a pure-Python transcription of RFC 7693, for round
  counts 0 to 130 and both finalisation flags.
- `tests/test_digest.py` compares the digest against `hashlib.blake2b` for
  fourteen message lengths, five key lengths, salt, person, and incremental
  updates in six chunk sizes.

## License

MIT
