"""Deterministic JSON encoding used for signed registry documents.

There is deliberately no JCS or other canonicalisation layer: the registry
JSON file *is* the signed message. Every writer in the Red Pen toolchain emits
the same bytes so that signing, verification, and validation all see the exact
same input.

The format is:

* UTF-8, without a BOM;
* object keys sorted lexicographically (Python's ``sort_keys``);
* two-space indentation, ``", "``/``": "`` separators;
* LF line endings only;
* exactly one trailing newline.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Union

PathLike = Union[str, "os.PathLike[str]"]


class CanonicalError(ValueError):
    """Raised when a file is not in the deterministic registry format."""


def canonical_text(value: Any) -> str:
    """Return the deterministic JSON text for ``value``."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise CanonicalError(f"value cannot be encoded as JSON: {exc}") from exc
    return rendered + "\n"


def canonical_bytes(value: Any) -> bytes:
    """Return the deterministic JSON bytes for ``value``."""

    return canonical_text(value).encode("utf-8")


def load_json(path: PathLike) -> Any:
    """Load JSON without accepting a BOM or invalid UTF-8."""

    data = Path(path).read_bytes()
    return loads_strict(data, str(path))


def loads_strict(data: bytes, label: str = "document") -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalError(f"{label}: UTF-8 BOM is not allowed")
    if b"\r" in data:
        raise CanonicalError(f"{label}: CRLF line endings are not allowed; use LF")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError(f"{label}: not valid UTF-8: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CanonicalError(f"{label}: invalid JSON: {exc}") from exc


def check_canonical_bytes(data: bytes, label: str = "document") -> Any:
    """Validate exact canonical bytes and return the decoded value."""

    value = loads_strict(data, label)
    expected = canonical_bytes(value)
    if data != expected:
        raise CanonicalError(
            f"{label}: not in deterministic JSON format "
            "(sorted keys, two-space indent, LF, one trailing newline); "
            "run the registry formatter"
        )
    return value


def check_canonical_file(path: PathLike) -> Any:
    return check_canonical_bytes(Path(path).read_bytes(), str(path))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: PathLike) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(
    path: PathLike,
    data: bytes,
    *,
    mode: int = 0o644,
) -> None:
    """Write ``data`` to ``path`` atomically with the requested mode."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    temporary_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise
