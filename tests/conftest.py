import ast
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "python"))

_LIB = _ROOT / "dist" / "libmojo-blake2.so"

if not _LIB.exists():
    pytest.skip(
        "libmojo-blake2.so not built; run `bash build/build.sh`",
        allow_module_level=True,
    )


def _load_vectors():
    """The EIP-152 vectors the upstream package asserts in its own test()."""
    src = _ROOT / "tests" / "eip152_vectors.py"
    if not src.exists():
        return {}
    tree = ast.parse(src.read_text())
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ("FAST_EXAMPLES", "SLOW_EXAMPLES", "ERROR_EXAMPLES"):
                out[name] = ast.literal_eval(node.value)
    return out


VECTORS = _load_vectors()
needs_vectors = pytest.mark.skipif(
    not VECTORS, reason="tests/eip152_vectors.py is missing"
)
