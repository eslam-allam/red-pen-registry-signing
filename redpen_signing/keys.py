"""Minisign public-key parsing and fingerprinting.

A minisign public key file contains a comment line and one base64 line. The
decoded 42-byte value is:

* two bytes of algorithm tag (``Ed`` for Ed25519);
* eight bytes of key id in minisign little-endian order;
* 32 bytes of public key.

``key_id`` is the uppercase hex form of those eight id bytes **reversed** to
the conventional minisign/G1 order. ``fingerprint`` is the SHA-256 of the exact
``.pub`` file bytes, including its comment and trailing newline, not of the
decoded key. Both values are stable across tools and reveal no private
material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Union

PathLike = Union[str, "os.PathLike[str]"]

KEY_BYTES = 42
KEY_ID_OFFSET = 2
KEY_ID_LENGTH = 8
PUBLIC_KEY_LENGTH = 32
ALGORITHM = b"Ed"


class PublicKeyError(ValueError):
    """Raised when a public key file cannot be parsed safely."""


@dataclass(frozen=True)
class PublicKey:
    raw: bytes
    key_id: str
    fingerprint: str
    base64: str

    @property
    def algorithm(self) -> str:
        return self.raw[:2].decode("ascii")


def parse_public_key(data: Union[bytes, str], label: str = "public key") -> PublicKey:
    exact = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    try:
        text = exact.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicKeyError(f"{label}: not valid UTF-8") from exc

    candidates: list[bytes] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("untrusted comment:"):
            continue
        try:
            decoded = base64.b64decode(stripped, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) == KEY_BYTES and decoded.startswith(ALGORITHM):
            candidates.append(decoded)

    if not candidates:
        raise PublicKeyError(
            f"{label}: no minisign Ed25519 public key found "
            "(expected a comment line and one base64 line)"
        )
    if len({item for item in candidates}) > 1:
        raise PublicKeyError(f"{label}: contains more than one public key")

    raw = candidates[0]
    key_id = raw[KEY_ID_OFFSET : KEY_ID_OFFSET + KEY_ID_LENGTH][::-1].hex().upper()
    fingerprint = hashlib.sha256(exact).hexdigest()
    return PublicKey(
        raw=raw,
        key_id=key_id,
        fingerprint=fingerprint,
        base64=base64.b64encode(raw).decode("ascii"),
    )


def read_public_key(path: PathLike) -> PublicKey:
    return parse_public_key(Path(path).read_bytes(), str(path))


def key_id_from_text(text: str) -> str:
    return parse_public_key(text).key_id


def fingerprint_from_text(text: str) -> str:
    return parse_public_key(text).fingerprint


def is_hex_key_id(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-F]{16}", value))
