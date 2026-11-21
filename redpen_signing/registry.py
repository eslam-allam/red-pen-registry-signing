"""Registry format, signing metadata, and release metadata helpers."""

from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from .canonical import load_json, sha256_file
from .keys import PublicKey

PathLike = Union[str, "os.PathLike[str]"]

SCHEMA = 7
MANIFEST_SCHEMA = 5
API_VERSION = 2
KIND = "red-pen-adapters"
RELEASE_SCHEMA = 1
RELEASE_KIND = "red-pen-adapters-release"

REGISTRY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
TIER_REGISTRY_IDS = {"official": "red-pen-official", "community": "red-pen-community"}
RESERVED_REGISTRY_IDS = frozenset(TIER_REGISTRY_IDS.values())
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_SEQUENCE = 2**31 - 1
MAX_EXPIRES_DAYS = 366
CLOCK_SKEW = timedelta(minutes=5)


class RegistryError(ValueError):
    """A registry document or configuration is not safe to sign."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise RegistryError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_timestamp(value: str, label: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise RegistryError(
            f"{label} must be an RFC 3339 UTC timestamp like 2026-01-31T12:00:00Z"
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise RegistryError(f"{label} is not a real date: {value}") from exc


def load_config(path: PathLike) -> dict[str, Any]:
    config = load_json(path)
    if not isinstance(config, dict):
        raise RegistryError(f"{path}: registry configuration must be an object")
    return config


def load_registry(path: PathLike) -> dict[str, Any]:
    registry = load_json(path)
    if not isinstance(registry, dict):
        raise RegistryError(f"{path}: registry must be a JSON object")
    return registry


def signing_settings(config: dict[str, Any]) -> dict[str, Any]:
    settings = config.get("signing")
    if not isinstance(settings, dict):
        raise RegistryError("registry.config.json: signing settings are missing")
    return settings


def expires_days(config: dict[str, Any]) -> int:
    value = signing_settings(config).get("expiresInDays", 180)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RegistryError("signing.expiresInDays must be an integer")
    if not 1 <= value <= MAX_EXPIRES_DAYS:
        raise RegistryError(
            f"signing.expiresInDays must be between 1 and {MAX_EXPIRES_DAYS}"
        )
    return value


def registry_identity(registry: dict[str, Any]) -> tuple[str, int]:
    registry_id = registry.get("registryId")
    sequence = registry.get("sequence")
    if not isinstance(registry_id, str) or not REGISTRY_ID.fullmatch(registry_id):
        raise RegistryError(
            "registryId must be a lowercase slug matching "
            "^[a-z0-9][a-z0-9._-]{0,127}$"
        )
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise RegistryError("sequence must be an integer")
    if not 1 <= sequence <= MAX_SEQUENCE:
        raise RegistryError(f"sequence must be between 1 and {MAX_SEQUENCE}")
    return registry_id, sequence


def trusted_comment(registry_id: str, sequence: int) -> str:
    if not REGISTRY_ID.fullmatch(registry_id):
        raise RegistryError("invalid registryId for a trusted comment")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise RegistryError("invalid sequence for a trusted comment")
    return f"registryId={registry_id} sequence={sequence}"


def parse_trusted_comment(comment: str) -> tuple[str, int]:
    match = re.fullmatch(r"registryId=([a-z0-9][a-z0-9._-]{0,127}) sequence=(\d+)", comment)
    if not match:
        raise RegistryError(
            "trusted comment must be exactly 'registryId=<id> sequence=<n>'"
        )
    sequence = int(match.group(2))
    if sequence < 1:
        raise RegistryError("trusted comment sequence must be positive")
    return match.group(1), sequence


def assert_registry_shape(
    registry: dict[str, Any],
    *,
    config: Optional[dict[str, Any]] = None,
    require_fresh: bool = True,
    now: Optional[datetime] = None,
) -> tuple[str, int]:
    if not isinstance(registry, dict):
        raise RegistryError("registry must be a JSON object")
    if "name" in registry:
        raise RegistryError(
            "registry must not contain a root name; adapter names live on "
            "the entries"
        )
    if registry.get("schema") != SCHEMA:
        raise RegistryError(f"registry schema must be {SCHEMA}")
    if registry.get("kind") != KIND:
        raise RegistryError(f"registry kind must be {KIND!r}")
    registry_id, sequence = registry_identity(registry)

    if config is not None:
        configured = config.get("registryId")
        if configured != registry_id:
            raise RegistryError(
                f"registryId {registry_id!r} does not match registry.config.json "
                f"({configured!r})"
            )
        expected_id = TIER_REGISTRY_IDS.get(config.get("tier"))
        if expected_id is not None and registry_id != expected_id:
            raise RegistryError(
                f"{config.get('tier')} registries must use registryId "
                f"{expected_id!r}"
            )
        if (
            config.get("tier") == "third-party"
            and registry_id in RESERVED_REGISTRY_IDS
        ):
            raise RegistryError(
                "third-party registries may not use a reserved "
                "official/community registryId"
            )

    publisher = registry.get("publisher")
    if not isinstance(publisher, str):
        raise RegistryError("publisher must be a string")
    if not publisher.strip():
        raise RegistryError("publisher must not be empty")
    if len(publisher) > 256:
        raise RegistryError("publisher must be at most 256 characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in publisher):
        raise RegistryError("publisher must not contain control characters")

    issued_at = parse_timestamp(registry.get("issuedAt"), "issuedAt")
    expires_at = parse_timestamp(registry.get("expiresAt"), "expiresAt")
    if expires_at <= issued_at:
        raise RegistryError("expiresAt must be later than issuedAt")
    if expires_at - issued_at > timedelta(days=MAX_EXPIRES_DAYS):
        raise RegistryError(
            f"registry lifetime must not exceed {MAX_EXPIRES_DAYS} days"
        )

    current = now or utc_now()
    if require_fresh:
        if issued_at > current + CLOCK_SKEW:
            raise RegistryError("issuedAt is in the future")
        if expires_at <= current:
            raise RegistryError("registry signature has expired; re-sign the registry")

    adapters = registry.get("adapters")
    if not isinstance(adapters, list) or not adapters:
        raise RegistryError("adapters must be a non-empty array")
    seen: set[str] = set()
    for index, entry in enumerate(adapters):
        if not isinstance(entry, dict):
            raise RegistryError(f"adapters[{index}] must be an object")
        adapter_id = entry.get("id")
        if not isinstance(adapter_id, str) or not adapter_id:
            raise RegistryError(f"adapters[{index}].id must be a non-empty string")
        if adapter_id in seen:
            raise RegistryError(f"duplicate adapter id {adapter_id!r}")
        seen.add(adapter_id)
        if entry.get("folder") != adapter_id:
            raise RegistryError(
                f"adapter {adapter_id!r}: folder must equal id"
            )
        if entry.get("apiVersion") != API_VERSION:
            raise RegistryError(
                f"adapter {adapter_id!r}: apiVersion must be {API_VERSION}"
            )
        files = entry.get("files")
        if not isinstance(files, list) or not files:
            raise RegistryError(f"adapter {adapter_id!r}: files must be a non-empty array")
        for declared in files:
            if not isinstance(declared, dict):
                raise RegistryError(
                    f"adapter {adapter_id!r}: every file must be an object"
                )
            if not safe_relative_path(declared.get("path")):
                raise RegistryError(
                    f"adapter {adapter_id!r}: unsafe file path "
                    f"{declared.get('path')!r}"
                )
            digest = declared.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise RegistryError(
                    f"adapter {adapter_id!r}: file needs a lowercase sha256"
                )

    return registry_id, sequence


def safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("/") or "\\" in value or ":" in value:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def next_sequence(current: int, base_sequence: int = 0) -> int:
    if not isinstance(current, int) or isinstance(current, bool) or current < 0:
        raise RegistryError("current sequence must be a non-negative integer")
    if not isinstance(base_sequence, int) or isinstance(base_sequence, bool):
        raise RegistryError("base sequence must be an integer")
    if base_sequence < 0:
        raise RegistryError("base sequence must not be negative")
    value = max(current, base_sequence) + 1
    if value > MAX_SEQUENCE:
        raise RegistryError("sequence overflow")
    return value


def prepare_registry(
    registry: dict[str, Any],
    config: dict[str, Any],
    *,
    base_sequence: int = 0,
    now: Optional[datetime] = None,
    expire_days: Optional[int] = None,
) -> dict[str, Any]:
    """Return a copied registry with the next sequence and fresh timestamps."""

    assert_registry_shape(registry, config=config, require_fresh=False)
    _, current = registry_identity(registry)
    current_time = (now or utc_now()).astimezone(timezone.utc).replace(microsecond=0)
    days = expires_days(config) if expire_days is None else expire_days
    if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= MAX_EXPIRES_DAYS:
        raise RegistryError("expiry days are out of range")

    prepared = copy.deepcopy(registry)
    prepared["sequence"] = next_sequence(current, base_sequence)
    prepared["issuedAt"] = format_timestamp(current_time)
    prepared["expiresAt"] = format_timestamp(current_time + timedelta(days=days))
    assert_registry_shape(prepared, config=config, require_fresh=True, now=current_time)
    return prepared


def build_release(
    registry: dict[str, Any],
    config: dict[str, Any],
    *,
    registry_sha256: str,
    signature_sha256: str,
    public_key: PublicKey,
    signer_commit: str,
    workflow_run: Optional[str] = None,
    tag: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> dict[str, Any]:
    registry_id, sequence = registry_identity(registry)
    if config.get("registryId") != registry_id:
        raise RegistryError("registryId does not match registry.config.json")
    expected_id = TIER_REGISTRY_IDS.get(config.get("tier"))
    if expected_id is not None and registry_id != expected_id:
        raise RegistryError(
            f"{config.get('tier')} registries must use registryId {expected_id!r}"
        )
    if (
        config.get("tier") == "third-party"
        and registry_id in RESERVED_REGISTRY_IDS
    ):
        raise RegistryError(
            "third-party registries may not use a reserved official/community registryId"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", signer_commit):
        raise RegistryError("signer commit must be a full 40-character SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", registry_sha256):
        raise RegistryError("invalid registry SHA-256")
    if not re.fullmatch(r"[0-9a-f]{64}", signature_sha256):
        raise RegistryError("invalid signature SHA-256")
    release_tag = tag or f"registry-v{sequence}"
    if release_tag != f"registry-v{sequence}":
        raise RegistryError("tag must be registry-v<sequence>")

    return {
        "schema": RELEASE_SCHEMA,
        "kind": RELEASE_KIND,
        "registryId": registry_id,
        "tier": config.get("tier"),
        "sequence": sequence,
        "tag": release_tag,
        "issuedAt": registry.get("issuedAt"),
        "expiresAt": registry.get("expiresAt"),
        "registrySha256": registry_sha256,
        "signatureSha256": signature_sha256,
        "keyId": public_key.key_id,
        "publicKeyFingerprint": public_key.fingerprint,
        "signerCommit": signer_commit,
        "workflowRun": workflow_run,
        "generatedAt": format_timestamp(generated_at or utc_now()),
    }


def release_json_bytes(release: dict[str, Any]) -> bytes:
    from .canonical import canonical_bytes

    return canonical_bytes(release)


def latest_tag_sequence(tags: Iterable[str]) -> int:
    latest = 0
    for tag in tags:
        match = re.fullmatch(r"registry-v(\d+)", tag.strip())
        if match:
            latest = max(latest, int(match.group(1)))
    return latest


def require_clean_release_artifacts(
    registry_path: PathLike,
    signature_path: PathLike,
    release_path: PathLike,
    config: Optional[dict[str, Any]] = None,
) -> None:
    """Reject artifacts whose bytes changed after signing."""

    registry = load_registry(registry_path)
    assert_registry_shape(registry, require_fresh=False)
    signature = Path(signature_path)
    if signature.stat().st_size > 16 * 1024:
        raise RegistryError("signature file is larger than the 16 KiB limit")
    release = load_json(release_path)
    if release.get("registrySha256") != sha256_file(registry_path):
        raise RegistryError("release.json registrySha256 does not match registry.json")
    if release.get("signatureSha256") != sha256_file(signature_path):
        raise RegistryError("release.json signatureSha256 does not match the signature")
    registry_id, sequence = registry_identity(registry)
    if release.get("registryId") != registry_id or release.get("sequence") != sequence:
        raise RegistryError("release.json does not describe this registry version")
    if release.get("tag") != f"registry-v{sequence}":
        raise RegistryError("release.json tag does not match the sequence")
    if release.get("issuedAt") != registry.get("issuedAt"):
        raise RegistryError("release.json issuedAt does not match the registry")
    if release.get("expiresAt") != registry.get("expiresAt"):
        raise RegistryError("release.json expiresAt does not match the registry")
    if config is not None:
        signing = config.get("signing") or {}
        if release.get("tier") != config.get("tier"):
            raise RegistryError("release.json tier does not match the config")
        if release.get("signerCommit") != signing.get("signerCommit"):
            raise RegistryError(
                "release.json signerCommit does not match the pinned signer"
            )
