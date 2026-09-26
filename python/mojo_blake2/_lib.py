"""ctypes bridge to the compiled Mojo kernels.

The shared library owns no memory.  Every buffer crosses the C ABI as a
64-bit address, so the argtypes below must stay ``c_int64`` for addresses;
``c_int`` truncates them and segfaults.
"""

from __future__ import annotations

import ctypes
import pathlib

import numpy as np

_HERE = pathlib.Path(__file__).resolve()
_ROOT = _HERE.parents[2]
_LIB_PATH = _ROOT / "dist" / "libmojo-blake2.so"

_A = ctypes.c_int64

# h 0..7, m 8..23, t 24..25, working vector 26..41, rounds 42, flag 43
SCRATCH_WORDS = 44

# a dedicated message-block buffer for the streaming kernel
BLOCK_WORDS = 16


def _load() -> ctypes.CDLL:
    if not _LIB_PATH.exists():
        raise RuntimeError(f"{_LIB_PATH} not found; run `bash build/build.sh` first")
    lib = ctypes.CDLL(str(_LIB_PATH))
    lib.b2_compress.restype = None
    lib.b2_compress.argtypes = [_A, _A, _A, _A, _A, _A, _A]
    lib.b2_compress_stream.restype = None
    lib.b2_compress_stream.argtypes = [_A, _A, _A, _A, _A, _A, _A]
    lib.b2_decode_parameters.restype = ctypes.c_int64
    lib.b2_decode_parameters.argtypes = [_A, _A, _A]
    lib.b2_decode_and_compress.restype = ctypes.c_int64
    lib.b2_decode_and_compress.argtypes = [_A, _A, _A, _A]
    return lib


lib = _load()


def scratch() -> np.ndarray:
    """A fresh zeroed scratch buffer in the layout the kernels expect."""
    return np.zeros(SCRATCH_WORDS, dtype=np.uint64)


def blocks() -> np.ndarray:
    """A 16-word message block buffer for ``b2_compress_stream``."""
    return np.zeros(BLOCK_WORDS, dtype=np.uint64)


def addr(a) -> int:
    return a.ctypes.data
