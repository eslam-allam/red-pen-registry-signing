from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from redpen_signing.canonical import canonical_bytes, sha256_file
from redpen_signing.keys import read_public_key
from redpen_signing.registry import REGISTRY_ID, RegistryError, assert_registry_shape
from redpen_signing.validate import (
    check_pin,
    ci_config,
    validate_registry_tree,
)

ROOT = Path(__file__).resolve().parent.parent


def write_tree(base: Path, *, registry_id: str = "test-registry") -> Path:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    (base / "demo").mkdir(parents=True)
    manifest = {
        "$schema": "../schemas/manifest.schema.json",
        "schema": 4,
        "id": "demo",
        "name": "Demo",
        "version": "1.0.0",
        "description": "Demo adapter",
        "author": "Red Pen tests",
        "extensions": ["txt"],
        "appliesTo": ["file"],
        "output": {"kinds": ["text"]},
        "permissions": [],
        "keyInput": [],
        "settings": [],
    }
    manifest_path = base / "demo" / "manifest.json"
    manifest_path.write_bytes(canonical_bytes(manifest))
    adapter = base / "demo" / "adapter.lua"
    adapter.write_text("app.result({ text = 'ok' })\n", encoding="utf-8")
    (base / "demo" / "README.md").write_text(
        "# Demo\n\n- **Version:** 1.0.0\n", encoding="utf-8"
    )
    config = {
        "schema": 1,
        "registryId": registry_id,
        "tier": "third-party",
        "repository": "owner/repo",
        "readmeBaseUrl": "https://raw.githubusercontent.com/owner/repo/main",
        "publisher": "Red Pen tests",
        "requireSignature": False,
        "signing": {
            "enabled": False,
            "environment": None,
            "keyFile": None,
            "expiresInDays": 180,
            "signerRepository": "owner/signer",
            "signerCommit": "a" * 40,
        },
    }
    registry = {
        "schema": 6,
        "kind": "red-pen-adapters",
        "registryId": registry_id,
        "name": "Test registry",
        "publisher": "Red Pen tests",
        "sequence": 1,
        "issuedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "adapters": [
            {
                "id": "demo",
                "name": "Demo",
                "version": "1.0.0",
                "description": "Demo adapter",
                "author": "Red Pen tests",
                "appliesTo": ["file"],
                "permissions": [],
                "extensions": ["txt"],
                "folder": "demo",
                "files": [
                    {"path": "adapter.lua", "sha256": sha256_file(adapter)},
                    {"path": "manifest.json", "sha256": sha256_file(manifest_path)},
                ],
                "readmeUrl": "https://raw.githubusercontent.com/owner/repo/main/demo/README.md",
            }
        ],
    }
    (base / "registry.config.json").write_bytes(canonical_bytes(config))
    (base / "registry.json").write_bytes(canonical_bytes(registry))
    return base


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="redpen-validate-test-")
        self.root = write_tree(Path(self.temp.name))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def errors(self) -> list[str]:
        return validate_registry_tree(self.root)["errors"]

    def mutate_registry(self, mutate) -> None:
        path = self.root / "registry.json"
        value = json.loads(path.read_text())
        mutate(value)
        path.write_bytes(canonical_bytes(value))

    def set_bootstrap(self, bootstrap, registry_bootstrap=None) -> None:
        manifest_path = self.root / "demo" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["bootstrap"] = bootstrap
        manifest_path.write_bytes(canonical_bytes(manifest))
        registry_path = self.root / "registry.json"
        registry = json.loads(registry_path.read_text())
        entry = registry["adapters"][0]
        entry["bootstrap"] = (
            bootstrap if registry_bootstrap is None else registry_bootstrap
        )
        for declared in entry["files"]:
            if declared["path"] == "manifest.json":
                declared["sha256"] = sha256_file(manifest_path)
        registry_path.write_bytes(canonical_bytes(registry))

    def update_manifest(self, mutate) -> None:
        manifest_path = self.root / "demo" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        mutate(manifest)
        manifest_path.write_bytes(canonical_bytes(manifest))
        registry_path = self.root / "registry.json"
        registry = json.loads(registry_path.read_text())
        for declared in registry["adapters"][0]["files"]:
            if declared["path"] == "manifest.json":
                declared["sha256"] = sha256_file(manifest_path)
        registry_path.write_bytes(canonical_bytes(registry))

    def add_managed_runtime(self) -> None:
        def mutate(manifest):
            manifest["settings"] = [
                {"key": "compiler", "label": "Compiler", "type": "text", "default": "16.2.0"}
            ]
            manifest["runtimes"] = [
                {"tool": "conda:gcc", "setting": "compiler", "version": "16.2.0"}
            ]
        self.update_manifest(mutate)
        registry_path = self.root / "registry.json"
        registry = json.loads(registry_path.read_text())
        manifest = json.loads((self.root / "demo" / "manifest.json").read_text())
        registry["adapters"][0]["runtimes"] = manifest["runtimes"]
        registry_path.write_bytes(canonical_bytes(registry))

    def test_valid_tree(self) -> None:
        result = validate_registry_tree(self.root)
        self.assertTrue(result["valid"], result["errors"])

    def test_publisher_must_be_string(self) -> None:
        self.mutate_registry(lambda value: value.update(publisher={"name": "x"}))
        self.assertTrue(any("publisher" in error for error in self.errors()))

    def test_files_must_be_objects(self) -> None:
        self.mutate_registry(
            lambda value: value["adapters"][0].update(files=["adapter.lua"])
        )
        self.assertTrue(any("files" in error for error in self.errors()))

    def test_unsafe_file_paths_rejected(self) -> None:
        for path in ("../escape", "/etc/passwd", "a:b", "a\\b", "a\x01b"):
            with self.subTest(path=path), tempfile.TemporaryDirectory(
                prefix="redpen-path-test-"
            ) as directory:
                root = write_tree(Path(directory))
                registry_path = root / "registry.json"
                value = json.loads(registry_path.read_text())
                value["adapters"][0]["files"].append(
                    {"path": path, "sha256": "0" * 64}
                )
                registry_path.write_bytes(canonical_bytes(value))
                errors = validate_registry_tree(root)["errors"]
                self.assertTrue(
                    any("unsafe file path" in error for error in errors), errors
                )

    def test_registry_id_rule_is_slug_and_g1_compatible(self) -> None:
        self.assertIsNotNone(REGISTRY_ID.fullmatch("red-pen-official"))
        self.assertIsNotNone(REGISTRY_ID.fullmatch("third_party.registry"))
        self.assertIsNotNone(REGISTRY_ID.fullmatch("a" * 128))
        self.assertIsNone(REGISTRY_ID.fullmatch("a" * 129))
        self.assertIsNone(REGISTRY_ID.fullmatch("../escape"))
        self.assertIsNone(REGISTRY_ID.fullmatch("Owner/Repo"))

    def test_noncanonical_config_rejected(self) -> None:
        path = self.root / "registry.config.json"
        path.write_text(json.dumps(json.loads(path.read_text()), indent=4) + "\n")
        errors = self.errors()
        self.assertTrue(any("deterministic JSON" in error for error in errors), errors)

    def test_enabled_signing_requires_existing_key_file(self) -> None:
        path = self.root / "registry.config.json"
        config = json.loads(path.read_text())
        config["signing"]["enabled"] = True
        config["signing"]["environment"] = "registry-signing-third-party"
        config["signing"]["keyFile"] = "keys/missing.pub"
        path.write_bytes(canonical_bytes(config))
        errors = self.errors()
        self.assertTrue(any("keyFile is missing" in error for error in errors), errors)

    def test_valid_bootstrap_pins(self) -> None:
        for value in (
            {"mise": "latest"},
            {"mise": "1.2.3"},
            {"mise": "v1.2.3"},
            {"mise": "1.2.3-rc.1+build.1"},
            {"mise": "v1.2.3-rc.1+build.1"},
            {"mise": "latest", "uv": "0.5.11"},
        ):
            with self.subTest(value=value), tempfile.TemporaryDirectory(
                prefix="redpen-bootstrap-test-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.add_managed_runtime()
                self.set_bootstrap(value)
                result = validate_registry_tree(root)
                self.assertTrue(result["valid"], result["errors"])

    def test_malformed_bootstrap_pins(self) -> None:
        for value in (
            {"mise": "any-version"},
            {"mise": "1.2"},
            {"uv": True},
            {"mise": "latest", "extra": "1.2.3"},
        ):
            with self.subTest(value=value), tempfile.TemporaryDirectory(
                prefix="redpen-bootstrap-test-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.set_bootstrap(value)
                result = validate_registry_tree(root)
                self.assertFalse(result["valid"], value)
                self.assertTrue(
                    any("bootstrap" in error for error in result["errors"]),
                    result["errors"],
                )

    def test_malformed_bootstrap_shapes(self) -> None:
        for value in (True, "latest", [], {}, 123, {"mise": ["latest"]}):
            with self.subTest(value=value), tempfile.TemporaryDirectory(
                prefix="redpen-bootstrap-shape-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.set_bootstrap(value)
                result = validate_registry_tree(root)
                self.assertFalse(result["valid"], value)
                self.assertTrue(
                    any("bootstrap" in error for error in result["errors"]),
                    result["errors"],
                )

    def test_bootstrap_mirror_one_side_only(self) -> None:
        self.add_managed_runtime()

        # Manifest only.
        self.update_manifest(lambda manifest: manifest.update({"bootstrap": {"mise": "latest"}}))
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

        # Registry only.
        self.update_manifest(lambda manifest: manifest.pop("bootstrap", None))
        registry_path = self.root / "registry.json"
        registry = json.loads(registry_path.read_text())
        registry["adapters"][0]["bootstrap"] = {"mise": "latest"}
        registry_path.write_bytes(canonical_bytes(registry))
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

        # Both sides but different values.
        self.set_bootstrap({"mise": "latest"}, {"mise": "v1.2.3"})
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

    def test_invalid_semver_bootstrap_pins(self) -> None:
        for value in (
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2",
            "1.2.3-01",
            "1.2.3-",
            "1.2.3+",
            "1.2.3-rc..1",
            "1.2.3-rc_1",
            "1.2.3+meta_1",
            "1.2.3.4",
            "latest-but-not",
        ):
            with self.subTest(version=value), tempfile.TemporaryDirectory(
                prefix="redpen-bootstrap-test-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.add_managed_runtime()
                self.set_bootstrap({"mise": value})
                result = validate_registry_tree(root)
                self.assertFalse(result["valid"], value)

    def test_managed_runtime_requires_mise(self) -> None:
        self.add_managed_runtime()
        result = validate_registry_tree(self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("managed runtimes need" in error for error in result["errors"]),
            result["errors"],
        )
        self.set_bootstrap({"uv": "0.5.11"})
        result = validate_registry_tree(self.root)
        self.assertTrue(
            any("managed runtimes need" in error for error in result["errors"]),
            result["errors"],
        )
        self.set_bootstrap({"mise": "latest"})
        self.assertTrue(validate_registry_tree(self.root)["valid"])

    def test_bootstrap_without_runtime_rejected(self) -> None:
        self.set_bootstrap({"mise": "latest"})
        result = validate_registry_tree(self.root)
        self.assertTrue(
            any("without a managed runtime" in error for error in result["errors"]),
            result["errors"],
        )

    def test_bootstrap_must_match_manifest(self) -> None:
        self.add_managed_runtime()
        self.set_bootstrap({"mise": "latest"}, {"mise": "v1.2.3"})
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

    def test_stale_release_requires_pre_signing_skip(self) -> None:
        (self.root / "release.json").write_bytes(
            canonical_bytes({"schema": 1, "sequence": 999})
        )
        errors = validate_registry_tree(self.root)["errors"]
        self.assertTrue(any("release.json" in error for error in errors), errors)
        pre_signing = validate_registry_tree(self.root, skip_release=True)
        self.assertTrue(pre_signing["valid"], pre_signing["errors"])

    def test_reserved_third_party_registry_id(self) -> None:
        shutil.rmtree(self.root)
        write_tree(self.root, registry_id="red-pen-official")
        errors = self.errors()
        self.assertTrue(any("reserved" in error for error in errors), errors)

    def test_self_signer_rejected(self) -> None:
        path = self.root / "registry.config.json"
        config = json.loads(path.read_text())
        config["signing"]["signerRepository"] = config["repository"]
        path.write_bytes(canonical_bytes(config))
        errors = self.errors()
        self.assertTrue(any("separate repository" in error for error in errors), errors)

    def test_official_signer_repository_enforced(self) -> None:
        shutil.rmtree(self.root)
        write_tree(self.root, registry_id="red-pen-official")
        path = self.root / "registry.config.json"
        config = json.loads(path.read_text())
        config["tier"] = "official"
        config["requireSignature"] = True
        config["signing"]["enabled"] = True
        config["signing"]["environment"] = "registry-signing-official"
        config["signing"]["signerRepository"] = "attacker/signer"
        path.write_bytes(canonical_bytes(config))
        errors = self.errors()
        self.assertTrue(any("signer repository" in error.lower() for error in errors), errors)

    def test_ci_config_requires_exact_tier_id(self) -> None:
        config = json.loads((self.root / "registry.config.json").read_text())
        config["tier"] = "official"
        config["registryId"] = "example"
        with self.assertRaises(RegistryError):
            ci_config(config)
        config["registryId"] = "red-pen-official"
        config["signing"]["enabled"] = True
        config["signing"]["environment"] = "registry-signing-community"
        with self.assertRaises(RegistryError):
            ci_config(config)
        config["signing"]["environment"] = "registry-signing-official"
        self.assertEqual(ci_config(config)["environment"], "registry-signing-official")


class KeyIdentityTests(unittest.TestCase):
    def test_matches_g1_published_key_ids_and_fingerprints(self) -> None:
        fixtures = Path(__file__).resolve().parent / "fixtures" / "g1-keys"
        expected = json.loads((fixtures / "expected.json").read_text(encoding="utf-8"))
        for name, values in expected.items():
            with self.subTest(key=name):
                key = read_public_key(fixtures / name)
                self.assertEqual(key.key_id, values["keyId"])
                self.assertEqual(key.fingerprint, values["fingerprint"])


class IsolationTests(unittest.TestCase):
    def test_dash_p_does_not_load_fake_registry_package(self) -> None:
        with tempfile.TemporaryDirectory(prefix="redpen-shadow-test-") as directory:
            shadow = Path(directory) / "redpen_signing"
            shadow.mkdir()
            (shadow / "__init__.py").write_text(
                "raise SystemExit('SHADOWED')\n", encoding="utf-8"
            )
            env = {
                "PATH": os.environ.get("PATH", ""),
                "PYTHONPATH": str(ROOT),
                "LANG": "C.UTF-8",
            }
            if os.environ.get("MINISIGN_BIN"):
                env["MINISIGN_BIN"] = os.environ["MINISIGN_BIN"]
            elif shutil.which("minisign") is None:
                self.skipTest("minisign is not installed")
            result = subprocess.run(
                [sys.executable, "-P", "-m", "redpen_signing.cli", "version"],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("SHADOWED", result.stdout + result.stderr)
            self.assertIn("signerVersion", result.stdout)


class PinTests(unittest.TestCase):
    @staticmethod
    def git(repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_pin_must_be_reachable_from_main(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        with tempfile.TemporaryDirectory(prefix="redpen-pin-test-") as directory:
            root = Path(directory)
            origin = root / "origin.git"
            subprocess.run(["git", "init", "--bare", str(origin)], check=True)
            work = root / "work"
            subprocess.run(["git", "init", str(work)], check=True)
            self.git(work, "config", "user.email", "test@example.invalid")
            self.git(work, "config", "user.name", "Test")
            self.git(work, "remote", "add", "origin", str(origin))
            (work / "a").write_text("a", encoding="utf-8")
            self.git(work, "add", "a")
            self.git(work, "commit", "-m", "a")
            self.git(work, "push", "-u", "origin", "HEAD:main")
            (work / "b").write_text("b", encoding="utf-8")
            self.git(work, "add", "b")
            self.git(work, "commit", "-m", "b")
            self.git(work, "push", "origin", "HEAD:main")
            merged = self.git(work, "rev-parse", "HEAD")

            clone = root / "clone"
            subprocess.run(["git", "clone", str(origin), str(clone)], check=True)
            check_pin(clone, merged)

            self.git(work, "checkout", "-b", "side")
            (work / "side").write_text("side", encoding="utf-8")
            self.git(work, "add", "side")
            self.git(work, "commit", "-m", "side")
            unmerged = self.git(work, "rev-parse", "HEAD")
            with self.assertRaises(RegistryError):
                check_pin(clone, unmerged)
            with self.assertRaises(RegistryError):
                check_pin(clone, merged, expected_repository="attacker/signer")

            shallow = root / "shallow"
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", "main", f"file://{origin}", str(shallow)],
                check=True,
            )
            first = self.git(work, "rev-list", "--max-parents=0", "HEAD")
            check_pin(shallow, first)


if __name__ == "__main__":
    unittest.main()
