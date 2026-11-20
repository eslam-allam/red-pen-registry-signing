from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import secrets
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from redpen_signing.askpass import write_askpass
from redpen_signing.canonical import (
    CanonicalError,
    canonical_bytes,
    check_canonical_bytes,
    sha256_file,
)
from redpen_signing.keys import PublicKeyError, parse_public_key, read_public_key
from redpen_signing.minisign import (
    MinisignError,
    find_minisign,
    generate_key,
    minisign_version,
    sign_file,
    verify_file,
    _safe_environment,
)
from redpen_signing.registry import (
    RegistryError,
    assert_registry_shape,
    build_release,
    latest_tag_sequence,
    prepare_registry,
    require_clean_release_artifacts,
    trusted_comment,
)
from redpen_signing.sign import (
    install_secret_key_from_env,
    sign_registry,
    sign_test_roundtrip,
)
from redpen_signing.verify import SignatureError, verify_registry


def has_minisign() -> bool:
    try:
        find_minisign()
        return True
    except MinisignError:
        return False


HAS_MINISIGN = has_minisign()


def make_config(registry_id: str = "test-registry") -> dict:
    return {
        "schema": 1,
        "registryId": registry_id,
        "tier": "third-party",
        "signing": {"enabled": False, "expiresInDays": 180},
    }


def make_registry(sequence: int = 1, registry_id: str = "test-registry") -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "schema": 6,
        "kind": "red-pen-adapters",
        "registryId": registry_id,
        "name": "Test registry",
        "publisher": "Red Pen tests",
        "sequence": sequence,
        "issuedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "adapters": [
            {
                "id": "demo",
                "folder": "demo",
                "files": [{"path": "manifest.json", "sha256": "0" * 64}],
            }
        ],
    }


@unittest.skipUnless(HAS_MINISIGN, "minisign is not installed")
class MinisignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="redpen-signer-test-")
        self.root = Path(self.temp.name)
        self.password = secrets.token_urlsafe(24)
        self.secret = self.root / "test.key"
        self.public = self.root / "test.pub"
        generate_key(self.secret, self.public, self.password)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_generate_and_sign_exact_bytes(self) -> None:
        message = self.root / "registry.json"
        signature = self.root / "registry.json.minisig"
        message.write_bytes(canonical_bytes(make_registry()))
        sign_file(
            self.secret,
            message,
            signature,
            "registryId=test-registry sequence=1",
            self.password,
        )
        self.assertTrue(verify_file(self.public, message, signature))

        original = message.read_bytes()
        message.write_bytes(original + b" ")
        self.assertFalse(verify_file(self.public, message, signature))

    def test_roundtrip_and_tamper(self) -> None:
        result = sign_test_roundtrip(
            self._write_registry(),
            make_config(),
            password=self.password,
            directory=self.root / "roundtrip",
        )
        self.assertTrue(result["tamperRejected"])
        self.assertEqual(result["sequence"], 2)
        self.assertRegex(result["keyId"], r"^[0-9A-F]{16}$")
        self.assertRegex(result["fingerprint"], r"^[0-9a-f]{64}$")

    def test_wrong_key_rejected(self) -> None:
        other_secret = self.root / "other.key"
        other_public = self.root / "other.pub"
        generate_key(other_secret, other_public, self.password, force=True)
        registry = self._write_registry()
        signature = self.root / "registry.json.minisig"
        result = sign_registry(
            registry,
            signature,
            self.secret,
            self.password,
            self.public,
            config=make_config(),
        )
        with self.assertRaises(SignatureError):
            verify_registry(registry, signature, other_public)

    def test_wrong_trusted_comment_rejected(self) -> None:
        registry = self._write_registry()
        signature = self.root / "registry.json.minisig"
        sign_file(
            self.secret,
            registry,
            signature,
            "registryId=test-registry sequence=99",
            self.password,
        )
        with self.assertRaises(SignatureError):
            verify_registry(registry, signature, self.public)

    def test_replay_lower_sequence_rejected(self) -> None:
        registry = self._write_registry()
        signature = self.root / "registry.json.minisig"
        sign_registry(
            registry,
            signature,
            self.secret,
            self.password,
            self.public,
            config=make_config(),
        )
        with self.assertRaises(SignatureError):
            verify_registry(registry, signature, self.public, min_sequence=2)
        verify_registry(registry, signature, self.public, min_sequence=1)

    def test_expired_index_rejected(self) -> None:
        registry = make_registry()
        registry["issuedAt"] = "2020-01-01T00:00:00Z"
        registry["expiresAt"] = "2020-02-01T00:00:00Z"
        path = self.root / "expired.json"
        signature = self.root / "expired.json.minisig"
        path.write_bytes(canonical_bytes(registry))
        sign_file(
            self.secret,
            path,
            signature,
            "registryId=test-registry sequence=1",
            self.password,
        )
        with self.assertRaises(SignatureError) as caught:
            verify_registry(path, signature, self.public)
        self.assertIn("expired", str(caught.exception))

    def test_noncanonical_registry_rejected(self) -> None:
        registry = self.root / "registry.json"
        registry.write_text(
            json.dumps(make_registry(), indent=4) + "\n", encoding="utf-8"
        )
        signature = self.root / "registry.json.minisig"
        with self.assertRaises(CanonicalError):
            sign_registry(
                registry,
                signature,
                self.secret,
                self.password,
                self.public,
                config=make_config(),
            )

    def test_key_id_and_fingerprint(self) -> None:
        key = read_public_key(self.public)
        self.assertEqual(len(key.raw), 42)
        self.assertEqual(key.algorithm, "Ed")
        self.assertRegex(key.key_id, r"^[0-9A-F]{16}$")
        self.assertRegex(key.fingerprint, r"^[0-9a-f]{64}$")
        import hashlib
        self.assertEqual(
            key.fingerprint, hashlib.sha256(self.public.read_bytes()).hexdigest()
        )

    def _write_registry(self) -> Path:
        path = self.root / "registry.json"
        path.write_bytes(canonical_bytes(make_registry()))
        return path


class FormatTests(unittest.TestCase):
    def test_canonical_writer(self) -> None:
        value = {"z": "é", "a": [2, 1], "nested": {"b": True, "a": None}}
        data = canonical_bytes(value)
        self.assertTrue(data.endswith(b"\n"))
        self.assertNotIn(b"\r", data)
        self.assertEqual(
            data,
            b'{\n  "a": [\n    2,\n    1\n  ],\n  "nested": {\n    "a": null,\n    "b": true\n  },\n  "z": "\xc3\xa9"\n}\n',
        )
        self.assertEqual(check_canonical_bytes(data), value)

    def test_rejects_crlf_and_bom(self) -> None:
        with self.assertRaises(CanonicalError):
            check_canonical_bytes(b'{\r\n  "a": 1\r\n}\r\n')
        with self.assertRaises(CanonicalError):
            check_canonical_bytes(b'\xef\xbb\xbf{\n  "a": 1\n}\n')

    def test_rejects_unsorted_keys(self) -> None:
        with self.assertRaises(CanonicalError):
            check_canonical_bytes(b'{\n  "b": 1,\n  "a": 2\n}\n')


class RegistryTests(unittest.TestCase):
    def test_prepare_uses_highest_sequence(self) -> None:
        prepared = prepare_registry(
            make_registry(sequence=4), make_config(), base_sequence=7
        )
        self.assertEqual(prepared["sequence"], 8)
        self.assertNotEqual(prepared["issuedAt"], "1970-01-01T00:00:00Z")
        assert_registry_shape(prepared, config=make_config())

    def test_expired_registry_fails_fresh_check(self) -> None:
        registry = make_registry()
        registry["issuedAt"] = "2020-01-01T00:00:00Z"
        registry["expiresAt"] = "2020-02-01T00:00:00Z"
        with self.assertRaises(RegistryError):
            assert_registry_shape(registry)

    def test_wrong_registry_id_fails(self) -> None:
        with self.assertRaises(RegistryError):
            assert_registry_shape(make_registry(), config=make_config("other"))

    def test_duplicate_adapter_ids_fail(self) -> None:
        registry = make_registry()
        registry["adapters"].append(dict(registry["adapters"][0]))
        with self.assertRaises(RegistryError):
            assert_registry_shape(registry)

    def test_trusted_comment_roundtrip(self) -> None:
        self.assertEqual(
            trusted_comment("test-registry", 12),
            "registryId=test-registry sequence=12",
        )

    def test_latest_tag_sequence(self) -> None:
        self.assertEqual(
            latest_tag_sequence(["registry-v1", "registry-v10", "other", "registry-v2"]),
            10,
        )

    def test_tier_registry_id_mapping(self) -> None:
        official = make_config("red-pen-official")
        official["tier"] = "official"
        assert_registry_shape(make_registry(registry_id="red-pen-official"), config=official)
        with self.assertRaises(RegistryError):
            assert_registry_shape(make_registry(registry_id="example-registry"), config=official)
        community = make_config("red-pen-community")
        community["tier"] = "community"
        assert_registry_shape(make_registry(registry_id="red-pen-community"), config=community)

    def test_publisher_must_be_string(self) -> None:
        registry = make_registry()
        registry["publisher"] = {"name": "Test"}
        with self.assertRaises(RegistryError):
            assert_registry_shape(registry)

    def test_third_party_reserved_registry_id_rejected(self) -> None:
        with self.assertRaises(RegistryError):
            assert_registry_shape(
                make_registry(registry_id="red-pen-official"),
                config=make_config("red-pen-official"),
            )

    def test_safe_environment_excludes_password(self) -> None:
        os.environ["MINISIGN_PASSWORD"] = "should-not-leak"
        try:
            self.assertNotIn("MINISIGN_PASSWORD", _safe_environment())
        finally:
            del os.environ["MINISIGN_PASSWORD"]

    def test_release_metadata(self) -> None:
        key = parse_public_key(
            "untrusted comment: test\n"
            + base64.b64encode(b"Ed" + bytes(range(8)) + bytes(range(32, 64))).decode()
            + "\n"
        )
        release = build_release(
            make_registry(sequence=3),
            make_config(),
            registry_sha256="a" * 64,
            signature_sha256="b" * 64,
            public_key=key,
            signer_commit="c" * 40,
            tag="registry-v3",
        )
        self.assertEqual(release["sequence"], 3)
        self.assertEqual(release["tag"], "registry-v3")
        self.assertEqual(release["keyId"], key.key_id)

    def test_clean_release_artifacts_check_config_and_digests(self) -> None:
        key = parse_public_key(
            "untrusted comment: test\n"
            + base64.b64encode(b"Ed" + bytes(range(8)) + bytes(range(32, 64))).decode()
            + "\n"
        )
        config = make_config()
        config["signing"]["signerCommit"] = "c" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "registry.json"
            signature_path = root / "registry.json.minisig"
            release_path = root / "release.json"
            registry_path.write_bytes(canonical_bytes(make_registry(sequence=3)))
            signature_path.write_text(
                "untrusted comment: test\nAAAA\ntrusted comment: "
                "registryId=test-registry sequence=3\nBBBB\n",
                encoding="utf-8",
            )
            release = build_release(
                make_registry(sequence=3),
                config,
                registry_sha256=sha256_file(registry_path),
                signature_sha256=sha256_file(signature_path),
                public_key=key,
                signer_commit="c" * 40,
                tag="registry-v3",
            )
            release_path.write_bytes(canonical_bytes(release))
            require_clean_release_artifacts(
                registry_path, signature_path, release_path, config=config
            )
            release["signerCommit"] = "d" * 40
            release_path.write_bytes(canonical_bytes(release))
            with self.assertRaises(RegistryError):
                require_clean_release_artifacts(
                    registry_path, signature_path, release_path, config=config
                )

    def test_public_key_rejects_garbage(self) -> None:
        with self.assertRaises(PublicKeyError):
            parse_public_key("not a key")

    def test_askpass_embeds_token_and_is_private(self) -> None:
        import subprocess

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "git-askpass.sh"
            write_askpass(path, "test-token-123")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            password = subprocess.run(
                [str(path), "Password for 'https://github.com':"],
                check=True,
                capture_output=True,
                text=True,
            )
            username = subprocess.run(
                [str(path), "Username for 'https://github.com':"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(password.stdout.strip(), "test-token-123")
            self.assertEqual(username.stdout.strip(), "x-access-token")

    def test_secret_key_install_is_private(self) -> None:
        encoded = base64.b64encode(
            b"untrusted comment: test secret key\nAAAA\n"
        ).decode()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "minisign.key"
            install_secret_key_from_env(
                "TEST_SECRET", target, environ={"TEST_SECRET": encoded}
            )
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertTrue(target.read_bytes().startswith(b"untrusted comment:"))

    def test_secret_key_install_rejects_bad_base64(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "minisign.key"
            with self.assertRaises(Exception):
                install_secret_key_from_env(
                    "TEST_SECRET", target, environ={"TEST_SECRET": "!!!"}
                )


@unittest.skipUnless(HAS_MINISIGN, "minisign is not installed")
class VersionTests(unittest.TestCase):
    def test_minisign_version(self) -> None:
        self.assertRegex(minisign_version(), r"minisign \d+\.\d+")


if __name__ == "__main__":
    unittest.main()
