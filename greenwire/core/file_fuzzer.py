from __future__ import annotations

"""Simple fuzzing helpers for file-based parsers.

These utilities mutate image, binary and text inputs to test parser
robustness. They are lightweight and do not depend on project specific
modules so they can be reused across tools.
"""

from pathlib import Path
from typing import Callable, List, Dict
import random
import io

from PIL import Image


def _mutate_bytes(data: bytes, mutations: int = 1) -> bytes:
    """Flip random bytes in ``data`` several times."""
    arr = bytearray(data)
    for _ in range(mutations):
        if not arr:
            break
        idx = random.randint(0, len(arr) - 1)
        arr[idx] ^= random.randint(0, 255)
    return bytes(arr)


def fuzz_image_file(path: Path, iterations: int = 10) -> List[Dict[str, object]]:
    """Repeatedly corrupt an image file and attempt to parse it.

    Parameters
    ----------
    path:
        Seed image file.
    iterations:
        Number of mutated samples to try.

    Returns
    -------
    list of dict
        Parsing results with success flag and any error messages.
    """
    seed = path.read_bytes()
    results: List[Dict[str, object]] = []
    for i in range(iterations):
        mutated = _mutate_bytes(seed, random.randint(1, 5))
        try:
            img = Image.open(io.BytesIO(mutated))
            img.verify()
            results.append({"iteration": i, "valid": True})
        except Exception as exc:  # noqa: BLE001
            results.append({"iteration": i, "valid": False, "error": str(exc)})
    return results


def fuzz_binary_file(
    path: Path,
    parser: Callable[[bytes], object] | None = None,
    iterations: int = 10,
) -> List[Dict[str, object]]:
    """Mutate a binary file and feed the results to ``parser``.

    If no parser function is provided, the data is simply converted to a
    hexadecimal string to simulate processing.
    """
    seed = path.read_bytes()
    parser = parser or (lambda b: b.hex())
    results: List[Dict[str, object]] = []
    for i in range(iterations):
        mutated = _mutate_bytes(seed, random.randint(1, 5))
        try:
            parser(mutated)
            results.append({"iteration": i, "error": None})
        except Exception as exc:  # noqa: BLE001
            results.append({"iteration": i, "error": str(exc)})
    return results


def fuzz_unusual_input(
    parser: Callable[[str], object], base: str, iterations: int = 10
) -> List[Dict[str, object]]:
    """Feed strings containing odd Unicode characters to ``parser``."""
    results: List[Dict[str, object]] = []
    for i in range(iterations):
        mutated = base + "".join(
            chr(random.randint(0x80, 0x10FFFF)) for _ in range(random.randint(1, 3))
        )
        try:
            parser(mutated)
            results.append({"iteration": i, "error": None})
        except Exception as exc:  # noqa: BLE001
            results.append({"iteration": i, "error": str(exc)})
    return results
