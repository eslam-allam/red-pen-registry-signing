"""Exact-byte verification of a signed registry."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from .canonical import CanonicalError, check_canonical_bytes, sha256_file
from .keys import PublicKey, read_public_key
from .minisign import verify_file
from .registry import (
    RegistryError,
    assert_registry_shape,
    parse_timestamp,
    parse_trusted_comment,
    registry_identity,
    trusted_comment,
    utc_now,
)

PathLike = Union[str, "os.PathLike[str]"]

MAX_SIGNATURE_BYTES = 16 * 1024


class SignatureError(ValueError):
    """A signature is missing, malformed, or does not match the registry."""


@dataclass(frozen=True)
class VerificationResult:
    registry_id: str
    sequence: int
    registry_sha256: str
    signature_sha256: str
    key_id: str
    fingerprint: str
    trusted_comment: str
    issued_at: str
    expires_at: str


def read_signature(path: PathLike) -> tuple[str, str]:
    signature_path = Path(path)
    if not signature_path.is_file():
        raise SignatureError(f"signature file is missing: {signature_path}")
    if signature_path.stat().st_size > MAX_SIGNATURE_BYTES:
        raise SignatureError("signature file is larger than the 16 KiB limit")
    try:
        lines = signature_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SignatureError("signature file is not UTF-8 text") from exc
    if len(lines) != 4:
        raise SignatureError(
            "signature file must contain an untrusted comment, signature, "
            "trusted comment, and global signature"
        )
    if not lines[0].startswith("untrusted comment: "):
        raise SignatureError("signature file has no untrusted comment")
    if not lines[2].startswith("trusted comment: "):
        raise SignatureError("signature file has no trusted comment")
    return lines[0], lines[2][len("trusted comment: ") :]


def verify_registry(
    registry_path: PathLike,
    signature_path: PathLike,
    public_key_path: PathLike,
    *,
    expected_registry_id: Optional[str] = None,
    expected_sequence: Optional[int] = None,
    min_sequence: Optional[int] = None,
    require_fresh: bool = True,
    require_canonical: bool = True,
    binary: Optional[str] = None,
) -> VerificationResult:
    data = Path(registry_path).read_bytes()
    try:
        if require_canonical:
            registry = check_canonical_bytes(data, str(registry_path))
        else:
            registry = json.loads(data.decode("utf-8"))
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignatureError(str(exc)) from exc

    try:
        registry_id, sequence = assert_registry_shape(
            registry, require_fresh=require_fresh
        )
    except RegistryError as exc:
        raise SignatureError(str(exc)) from exc

    if expected_registry_id is not None and registry_id != expected_registry_id:
        raise SignatureError(
            f"registryId {registry_id!r} does not match the expected "
            f"{expected_registry_id!r}"
        )
    if expected_sequence is not None and sequence != expected_sequence:
        raise SignatureError(
            f"sequence {sequence} does not match the expected {expected_sequence}"
        )
    if min_sequence is not None and sequence < min_sequence:
        raise SignatureError(
            f"replay refused: sequence {sequence} is lower than the known "
            f"sequence {min_sequence}"
        )

    _, comment = read_signature(signature_path)
    try:
        comment_id, comment_sequence = parse_trusted_comment(comment)
    except RegistryError as exc:
        raise SignatureError(str(exc)) from exc
    expected_comment = trusted_comment(registry_id, sequence)
    if comment != expected_comment or comment_id != registry_id or comment_sequence != sequence:
        raise SignatureError(
            "trusted comment does not match the registryId and sequence"
        )

    public_key: PublicKey = read_public_key(public_key_path)
    if not verify_file(
        public_key_path,
        registry_path,
        signature_path,
        binary=binary,
    ):
        raise SignatureError("minisign verification failed")

    issued_at = registry["issuedAt"]
    expires_at = registry["expiresAt"]
    parse_timestamp(issued_at, "issuedAt")
    parse_timestamp(expires_at, "expiresAt")

    return VerificationResult(
        registry_id=registry_id,
        sequence=sequence,
        registry_sha256=sha256_file(registry_path),
        signature_sha256=sha256_file(signature_path),
        key_id=public_key.key_id,
        fingerprint=public_key.fingerprint,
        trusted_comment=comment,
        issued_at=issued_at,
        expires_at=expires_at,
    )
