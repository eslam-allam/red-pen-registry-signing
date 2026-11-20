"""Sign a registry's exact bytes, then verify the result immediately."""

from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Optional, Union

from .canonical import atomic_write, check_canonical_bytes, sha256_file
from .keys import read_public_key
from .minisign import generate_key, sign_file
from .registry import (
    RegistryError,
    assert_registry_shape,
    registry_identity,
    trusted_comment,
)
from .verify import VerificationResult, verify_registry

PathLike = Union[str, "os.PathLike[str]"]

MAX_SECRET_KEY_BYTES = 8 * 1024


class SigningError(ValueError):
    """Signing failed or the signed artifact did not verify."""


def sign_registry(
    registry_path: PathLike,
    signature_path: PathLike,
    secret_key_path: PathLike,
    password: str,
    public_key_path: PathLike,
    *,
    config: Optional[dict] = None,
    expected_registry_id: Optional[str] = None,
    expected_sequence: Optional[int] = None,
    binary: Optional[str] = None,
) -> VerificationResult:
    data = Path(registry_path).read_bytes()
    registry = check_canonical_bytes(data, str(registry_path))
    secret = Path(secret_key_path)
    if secret.is_symlink():
        raise SigningError("refusing to use a symlinked secret key")
    if secret.is_file() and stat.S_IMODE(secret.stat().st_mode) & 0o077:
        raise SigningError("secret key file must not be group/world accessible")
    try:
        registry_id, sequence = assert_registry_shape(registry, config=config)
    except RegistryError as exc:
        raise SigningError(str(exc)) from exc

    if expected_registry_id is not None and registry_id != expected_registry_id:
        raise SigningError("registryId does not match the requested identity")
    if expected_sequence is not None and sequence != expected_sequence:
        raise SigningError("sequence does not match the requested sequence")

    comment = trusted_comment(registry_id, sequence)
    target = Path(signature_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        sign_file(
            secret_key_path,
            registry_path,
            temporary_path,
            comment,
            password,
            binary=binary,
        )
        # Verify before publishing the signature next to the registry.
        result = verify_registry(
            registry_path,
            temporary_path,
            public_key_path,
            expected_registry_id=registry_id,
            expected_sequence=sequence,
            binary=binary,
        )
        os.replace(temporary_path, target)
        return result
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def install_secret_key_from_env(
    env_name: str,
    output_path: PathLike,
    *,
    environ: Optional[dict[str, str]] = None,
) -> Path:
    """Decode a base64 minisign secret key from an environment variable.

    The value is never printed, copied to argv, or written anywhere except a
    0600 file at ``output_path``.
    """

    source = environ if environ is not None else os.environ
    encoded = source.get(env_name, "")
    if not encoded.strip():
        raise SigningError(f"{env_name} is empty or missing")
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SigningError(f"{env_name} is not valid base64") from exc
    if not decoded:
        raise SigningError(f"{env_name} decodes to an empty file")
    if len(decoded) > MAX_SECRET_KEY_BYTES:
        raise SigningError(f"{env_name} is larger than the secret-key limit")
    if b"untrusted comment:" not in decoded[:128]:
        raise SigningError(f"{env_name} does not look like a minisign secret key")
    target = Path(output_path)
    atomic_write(target, decoded, mode=0o600)
    os.chmod(target, 0o600)
    return target


def generate_ephemeral_keypair(
    directory: PathLike,
    password: str,
    *,
    binary: Optional[str] = None,
) -> tuple[Path, Path]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:  # pragma: no cover - non-POSIX
        pass
    secret = root / "test.key"
    public = root / "test.pub"
    generate_key(secret, public, password, force=True, binary=binary)
    return secret, public


def sign_test_roundtrip(
    registry_path: PathLike,
    config: dict,
    *,
    base_sequence: int = 0,
    password: str,
    directory: Optional[PathLike] = None,
    binary: Optional[str] = None,
) -> dict:
    """Prepare, sign, verify, and tamper-check a registry with a test key.

    This exercises the encrypted-key PTY path without touching any production
    secret. The caller owns the temporary directory and removes it.
    """

    from .canonical import canonical_bytes
    from .registry import prepare_registry

    if directory is None:
        raise SigningError("a temporary directory is required for the test key")

    root = Path(directory)
    secret, public = generate_ephemeral_keypair(root, password, binary=binary)
    registry = json.loads(Path(registry_path).read_text(encoding="utf-8"))
    prepared = prepare_registry(registry, config, base_sequence=base_sequence)
    message = root / "registry.test.json"
    signature = root / "registry.test.json.minisig"
    message.write_bytes(canonical_bytes(prepared))

    result = sign_registry(
        message,
        signature,
        secret,
        password,
        public,
        config=config,
        binary=binary,
    )

    tampered = root / "registry.tampered.json"
    tampered.write_bytes(message.read_bytes() + b" ")
    tamper_rejected = False
    try:
        verify_registry(tampered, signature, public, binary=binary)
    except Exception:
        tamper_rejected = True
    if not tamper_rejected:
        raise SigningError("a tampered registry still verified")

    return {
        "sequence": result.sequence,
        "registryId": result.registry_id,
        "keyId": result.key_id,
        "fingerprint": result.fingerprint,
        "registrySha256": result.registry_sha256,
        "signatureSha256": result.signature_sha256,
        "tamperRejected": True,
    }
