"""Mojo BLAKE2b with the API of the ``blake2b`` package.

``import mojo_blake2`` never imports the real ``blake2b`` package, so the two
install side by side.
"""

from .core import (
    BLOCK_SIZE,
    Blake2b,
    blake2b,
    compress,
    decode_and_compress,
    decode_parameters,
)

__all__ = [
    "BLOCK_SIZE",
    "Blake2b",
    "blake2b",
    "compress",
    "decode_and_compress",
    "decode_parameters",
]
__version__ = "0.1.0"
