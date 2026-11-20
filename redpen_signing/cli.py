"""Command-line entry point for the pinned Red Pen registry signer.

Examples (all secrets come from the environment, never argv):

    python -m redpen_signing.cli key-id --public-key keys/official-2026.pub
    python -m redpen_signing.cli install-secret-key --env MINISIGN_SECRET_KEY_B64 --out /tmp/key
    python -m redpen_signing.cli prepare --registry registry.json --config registry.config.json --out /tmp/registry.json --base-sequence 4
    python -m redpen_signing.cli sign --registry registry.json --sig registry.json.minisig --secret-key /tmp/key --public-key keys/official-2026.pub --config registry.config.json
    python -m redpen_signing.cli verify --registry registry.json --sig registry.json.minisig --public-key keys/official-2026.pub --config registry.config.json
    python -m redpen_signing.cli release --registry registry.json --sig registry.json.minisig --public-key keys/official-2026.pub --config registry.config.json --out release.json --signer-commit <sha>
    python -m redpen_signing.cli test-key --registry registry.json --config registry.config.json
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from .askpass import AskpassError, write_askpass
from .canonical import atomic_write, canonical_bytes, sha256_file
from .keys import PublicKeyError, read_public_key
from .minisign import MinisignError, minisign_version
from .registry import (
    RegistryError,
    assert_registry_shape,
    build_release,
    load_config,
    load_registry,
    prepare_registry,
    registry_identity,
    require_clean_release_artifacts,
)
from .sign import (
    SigningError,
    install_secret_key_from_env,
    sign_registry,
    sign_test_roundtrip,
)
from .validate import check_pin, ci_config, validate_registry_tree
from .verify import SignatureError, verify_registry


def _json(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _public_key(args, config: Optional[dict] = None):
    key_path = args.public_key
    if key_path is None and config is not None:
        key_path = (config.get("signing") or {}).get("keyFile")
    if not key_path:
        raise SystemExit("a public key is required (--public-key or signing.keyFile)")
    return read_public_key(key_path)


def command_key_id(args) -> int:
    key = read_public_key(args.public_key)
    _json(
        {
            "keyId": key.key_id,
            "fingerprint": key.fingerprint,
            "algorithm": key.algorithm,
            "publicKey": key.base64,
        }
    )
    return 0


def command_install_secret_key(args) -> int:
    path = install_secret_key_from_env(args.env, args.out)
    print(f"Installed secret key from {args.env} at {path} with mode 0600.")
    return 0


def command_prepare(args) -> int:
    config = load_config(args.config)
    registry = load_registry(args.registry)
    prepared = prepare_registry(
        registry,
        config,
        base_sequence=args.base_sequence,
        expire_days=args.expires_days,
    )
    atomic_write(args.out, canonical_bytes(prepared), mode=0o644)
    registry_id, sequence = registry_identity(prepared)
    print(
        f"Prepared {registry_id} sequence {sequence} "
        f"({prepared['issuedAt']} -> {prepared['expiresAt']})."
    )
    return 0


def command_sign(args) -> int:
    config = load_config(args.config) if args.config else None
    key = _public_key(args, config)
    password = os.environ.get(args.password_env, "")
    if not password:
        raise SystemExit(f"{args.password_env} is empty or missing")
    result = sign_registry(
        args.registry,
        args.sig,
        args.secret_key,
        password,
        args.public_key or (config or {}).get("signing", {}).get("keyFile"),
        config=config,
    )
    _json(
        {
            "registryId": result.registry_id,
            "sequence": result.sequence,
            "registrySha256": result.registry_sha256,
            "signatureSha256": result.signature_sha256,
            "keyId": key.key_id,
            "fingerprint": key.fingerprint,
            "trustedComment": result.trusted_comment,
        }
    )
    return 0


def command_verify(args) -> int:
    config = load_config(args.config) if args.config else None
    key = _public_key(args, config)
    expected_id = args.registry_id
    expected_sequence = args.sequence
    if config is not None:
        if expected_id is None:
            expected_id = config.get("registryId")
    result = verify_registry(
        args.registry,
        args.sig,
        args.public_key or (config or {}).get("signing", {}).get("keyFile"),
        expected_registry_id=expected_id,
        expected_sequence=expected_sequence,
        min_sequence=args.min_sequence,
        require_fresh=not args.allow_expired,
    )
    _json(
        {
            "valid": True,
            "registryId": result.registry_id,
            "sequence": result.sequence,
            "issuedAt": result.issued_at,
            "expiresAt": result.expires_at,
            "registrySha256": result.registry_sha256,
            "signatureSha256": result.signature_sha256,
            "keyId": result.key_id,
            "fingerprint": result.fingerprint,
            "trustedComment": result.trusted_comment,
        }
    )
    return 0


def command_release(args) -> int:
    config = load_config(args.config)
    registry = load_registry(args.registry)
    assert_registry_shape(registry, config=config)
    key = _public_key(args, config)
    release = build_release(
        registry,
        config,
        registry_sha256=sha256_file(args.registry),
        signature_sha256=sha256_file(args.sig),
        public_key=key,
        signer_commit=args.signer_commit,
        workflow_run=args.run_url,
        tag=args.tag,
    )
    atomic_write(args.out, canonical_bytes(release), mode=0o644)
    require_clean_release_artifacts(
        args.registry, args.sig, args.out, config=config
    )
    print(
        f"Wrote {args.out} for {release['registryId']} "
        f"sequence {release['sequence']}."
    )
    return 0


def command_test_key(args) -> int:
    config = load_config(args.config)
    password = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix="redpen-sign-test-") as directory:
        result = sign_test_roundtrip(
            args.registry,
            config,
            base_sequence=args.base_sequence,
            password=password,
            directory=directory,
        )
    _json({"testKey": True, **result})
    return 0


def command_version(args) -> int:
    from . import __version__

    _json(
        {
            "signerVersion": __version__,
            "minisignVersion": minisign_version(args.minisign),
        }
    )
    return 0


def command_write_askpass(args) -> int:
    token = os.environ.get(args.env, "")
    if not token:
        raise AskpassError(f"{args.env} is empty or missing")
    path = write_askpass(args.out, token)
    print(f"Wrote mode-0700 askpass helper at {path}.")
    return 0


def command_validate(args) -> int:
    result = validate_registry_tree(
        Path(args.root),
        registry_path=args.registry,
        config_path=args.config,
        require_signature=args.require_signature,
        verify_present=args.verify_signature,
        allow_expired=args.allow_expired,
        skip_release=args.skip_release,
    )
    if args.json:
        _json(result)
    elif result["valid"]:
        print(
            f"Validated {result['adapters']} adapter(s), "
            f"{result['registryId']} sequence {result['sequence']}."
        )
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
        print(f"{len(result['errors'])} validation error(s).", file=sys.stderr)
    return 0 if result["valid"] else 1


def command_ci_config(args) -> int:
    config = load_config(args.config)
    values = ci_config(config)
    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            for name, value in values.items():
                handle.write(f"{name}={value}\n")
    else:
        _json(values)
    return 0


def command_sequence(args) -> int:
    registry = load_registry(args.registry)
    _, sequence = registry_identity(registry)
    print(sequence)
    return 0


def command_check_pin(args) -> int:
    check_pin(
        args.repo_dir,
        args.commit,
        expected_repository=args.expected_repository,
        remote=args.remote,
        branch=args.branch,
    )
    print(f"Signer commit {args.commit} is reachable from {args.remote}/{args.branch}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign and verify Red Pen adapter registries."
    )
    parser.add_argument("--minisign", help="path to the minisign binary")
    subparsers = parser.add_subparsers(dest="command", required=True)

    key_id = subparsers.add_parser("key-id", help="print key id and fingerprint")
    key_id.add_argument("--public-key", required=True)
    key_id.set_defaults(func=command_key_id)

    install = subparsers.add_parser(
        "install-secret-key", help="decode a base64 secret key from the environment"
    )
    install.add_argument("--env", default="MINISIGN_SECRET_KEY_B64")
    install.add_argument("--out", required=True)
    install.set_defaults(func=command_install_secret_key)

    prepare = subparsers.add_parser(
        "prepare", help="bump sequence and write fresh registry bytes"
    )
    prepare.add_argument("--registry", required=True)
    prepare.add_argument("--config", required=True)
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--base-sequence", type=int, default=0)
    prepare.add_argument("--expires-days", type=int)
    prepare.set_defaults(func=command_prepare)

    sign = subparsers.add_parser("sign", help="sign a prepared registry")
    sign.add_argument("--registry", required=True)
    sign.add_argument("--sig", required=True)
    sign.add_argument("--secret-key", required=True)
    sign.add_argument("--public-key")
    sign.add_argument("--config")
    sign.add_argument("--password-env", default="MINISIGN_PASSWORD")
    sign.set_defaults(func=command_sign)

    verify = subparsers.add_parser("verify", help="verify a signed registry")
    verify.add_argument("--registry", required=True)
    verify.add_argument("--sig", required=True)
    verify.add_argument("--public-key")
    verify.add_argument("--config")
    verify.add_argument("--registry-id")
    verify.add_argument("--sequence", type=int)
    verify.add_argument("--min-sequence", type=int)
    verify.add_argument("--allow-expired", action="store_true")
    verify.set_defaults(func=command_verify)

    release = subparsers.add_parser("release", help="write release.json")
    release.add_argument("--registry", required=True)
    release.add_argument("--sig", required=True)
    release.add_argument("--public-key")
    release.add_argument("--config", required=True)
    release.add_argument("--out", required=True)
    release.add_argument("--signer-commit", required=True)
    release.add_argument("--run-url")
    release.add_argument("--tag")
    release.set_defaults(func=command_release)

    test_key = subparsers.add_parser(
        "test-key", help="prepare, sign, verify, and tamper-check with a test key"
    )
    test_key.add_argument("--registry", required=True)
    test_key.add_argument("--config", required=True)
    test_key.add_argument("--base-sequence", type=int, default=0)
    test_key.set_defaults(func=command_test_key)

    askpass = subparsers.add_parser(
        "write-askpass", help="write a mode-0700 GIT_ASKPASS helper"
    )
    askpass.add_argument("--out", required=True)
    askpass.add_argument("--env", default="GH_TOKEN")
    askpass.set_defaults(func=command_write_askpass)

    validate = subparsers.add_parser(
        "validate", help="validate schema 6 and the registry tree"
    )
    validate.add_argument("--root", default=".")
    validate.add_argument("--registry", default="registry.json")
    validate.add_argument("--config", default="registry.config.json")
    validate.add_argument("--require-signature", action="store_true")
    validate.add_argument("--verify-signature", action="store_true")
    validate.add_argument("--allow-expired", action="store_true")
    validate.add_argument("--skip-release", action="store_true")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=command_validate)

    ci = subparsers.add_parser("ci-config", help="emit signing settings for CI")
    ci.add_argument("--config", default="registry.config.json")
    ci.add_argument("--github-output")
    ci.set_defaults(func=command_ci_config)

    sequence = subparsers.add_parser("sequence", help="print the registry sequence")
    sequence.add_argument("--registry", default="registry.json")
    sequence.set_defaults(func=command_sequence)

    pin = subparsers.add_parser(
        "check-pin", help="require the signer commit to be reachable from main"
    )
    pin.add_argument("--repo-dir", default=".")
    pin.add_argument("--commit", required=True)
    pin.add_argument("--expected-repository")
    pin.add_argument("--remote", default="origin")
    pin.add_argument("--branch", default="main")
    pin.set_defaults(func=command_check_pin)

    version = subparsers.add_parser("version", help="print signer versions")
    version.set_defaults(func=command_version)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "minisign", None):
        os.environ["MINISIGN_BIN"] = args.minisign
    try:
        return args.func(args)
    except (
        RegistryError,
        SignatureError,
        SigningError,
        PublicKeyError,
        MinisignError,
        AskpassError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
