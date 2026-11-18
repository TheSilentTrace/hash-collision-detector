"""Hash generation helpers built on top of :mod:`hashlib`.

This module is intentionally small: it normalises algorithm names, hashes
text or raw bytes, and optionally truncates a digest to its first N bits so
that collisions can be demonstrated in a reasonable amount of time.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Optional, Tuple, Union

SUPPORTED_ALGORITHMS: Tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")

DISPLAY_NAMES: Dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

DIGEST_BITS: Dict[str, int] = {
    "md5": 128,
    "sha1": 160,
    "sha256": 256,
    "sha512": 512,
}


class UnsupportedAlgorithmError(ValueError):
    """Raised when an unknown hash algorithm name is requested."""


def normalize_algorithm(name: str) -> str:
    """Return the canonical lowercase key for ``name``.

    Accepts common spellings such as ``SHA-256``, ``sha_256`` or ``Sha256``.
    """
    if not isinstance(name, str) or not name.strip():
        raise UnsupportedAlgorithmError("Algorithm name must be a non-empty string.")
    key = name.strip().lower().replace("-", "").replace("_", "").replace(" ", "")
    if key not in SUPPORTED_ALGORITHMS:
        supported = ", ".join(DISPLAY_NAMES[a] for a in SUPPORTED_ALGORITHMS)
        raise UnsupportedAlgorithmError(
            f"Unsupported algorithm '{name}'. Supported algorithms: {supported}."
        )
    return key


def display_name(algorithm: str) -> str:
    """Human friendly algorithm name (``sha256`` -> ``SHA-256``)."""
    return DISPLAY_NAMES[normalize_algorithm(algorithm)]


def digest_bits(algorithm: str) -> int:
    """Full digest size of ``algorithm`` in bits."""
    return DIGEST_BITS[normalize_algorithm(algorithm)]


def _new_hasher(key: str):
    # MD5 / SHA-1 are used here for analysis, not security. ``usedforsecurity``
    # keeps them usable on FIPS-enabled systems (Python 3.9+).
    try:
        return hashlib.new(key, usedforsecurity=False)
    except TypeError:  # pragma: no cover - very old Python builds
        return hashlib.new(key)


def generate_hash(
    data: Union[str, bytes],
    algorithm: str = "sha256",
    truncate_bits: Optional[int] = None,
) -> str:
    """Return the hexadecimal digest of ``data``.

    Args:
        data: Text (encoded as UTF-8) or raw bytes to hash.
        algorithm: One of ``md5``, ``sha1``, ``sha256``, ``sha512``.
        truncate_bits: If given, keep only the first N bits of the digest.
            The result is zero padded to ``ceil(N / 4)`` hex characters.

    Raises:
        UnsupportedAlgorithmError: for unknown algorithms.
        TypeError: if ``data`` is neither ``str`` nor ``bytes``.
        ValueError: if ``truncate_bits`` is out of range.
    """
    key = normalize_algorithm(algorithm)

    if isinstance(data, str):
        raw = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
    else:
        raise TypeError(f"Cannot hash object of type {type(data).__name__}.")

    hasher = _new_hasher(key)
    hasher.update(raw)
    digest = hasher.digest()

    if truncate_bits is None:
        return digest.hex()

    total_bits = len(digest) * 8
    if not isinstance(truncate_bits, int) or isinstance(truncate_bits, bool):
        raise ValueError("truncate_bits must be an integer.")
    if not 1 <= truncate_bits <= total_bits:
        raise ValueError(
            f"truncate_bits must be between 1 and {total_bits} for "
            f"{DISPLAY_NAMES[key]}."
        )
    value = int.from_bytes(digest, "big") >> (total_bits - truncate_bits)
    width = (truncate_bits + 3) // 4
    return f"{value:0{width}x}"


def generate_all(data: Union[str, bytes]) -> Dict[str, str]:
    """Hash ``data`` with every supported algorithm."""
    return {alg: generate_hash(data, alg) for alg in SUPPORTED_ALGORITHMS}
