from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from redpen_signing.canonical import canonical_bytes, sha256_file
from redpen_signing.keys import read_public_key
from redpen_signing.registry import (
    API_VERSION,
    MANIFEST_SCHEMA,
    REGISTRY_ID,
    SCHEMA,
    RegistryError,
)
from redpen_signing.validate import (
    check_pin,
    ci_config,
    load_mirror_fields,
    load_schema,
    validate_registry_tree,
)

ROOT = Path(__file__).resolve().parent.parent


def write_tree(base: Path, *, registry_id: str = "test-registry") -> Path:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    (base / "demo").mkdir(parents=True)
    manifest = {
        "$schema": "../schemas/manifest.schema.json",
        "apiVersion": 2,
        "schema": 5,
        "id": "demo",
        "name": "Demo",
        "version": "1.0.0",
        "description": "Demo adapter",
        "author": "Red Pen tests",
        "icon": "https://example.invalid/icon.svg",
        "homepage": "https://example.invalid/demo",
        "extensions": ["txt"],
        "appliesTo": ["file"],
        "output": {"kinds": ["text"]},
        "permissions": [],
        "registry": [],
        "keyInput": [],
        "questionInput": [],
        "settings": [],
        "directories": [],
        "directoryPicker": {"mode": "r"},
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
        "schema": 7,
        "kind": "red-pen-adapters",
        "registryId": registry_id,
        "publisher": "Red Pen tests",
        "sequence": 1,
        "issuedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "adapters": [
            {
                "apiVersion": 2,
                "id": "demo",
                "name": "Demo",
                "version": "1.0.0",
                "description": "Demo adapter",
                "author": "Red Pen tests",
                "icon": "https://example.invalid/icon.svg",
                "homepage": "https://example.invalid/demo",
                "extensions": ["txt"],
                "appliesTo": ["file"],
                "output": {"kinds": ["text"]},
                "permissions": [],
                "registry": [],
                "keyInput": [],
                "questionInput": [],
                "settings": [],
                "directories": [],
                "directoryPicker": {"mode": "r"},
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
                {
                    "key": "compiler",
                    "label": "Compiler",
                    "type": "text",
                    "default": "16.2.0",
                }
            ]
            manifest["runtimes"] = [
                {"tool": "conda:gcc", "setting": "compiler", "version": "16.2.0"}
            ]

        self.update_manifest(mutate)
        registry_path = self.root / "registry.json"
        registry = json.loads(registry_path.read_text())
        manifest = json.loads((self.root / "demo" / "manifest.json").read_text())
        registry["adapters"][0]["settings"] = manifest["settings"]
        registry["adapters"][0]["runtimes"] = manifest["runtimes"]
        registry_path.write_bytes(canonical_bytes(registry))

    def set_permissions(self, permissions: list[str]) -> None:
        self.update_manifest(lambda manifest: manifest.update(permissions=permissions))
        self.mutate_registry(
            lambda registry: registry["adapters"][0].update(permissions=permissions)
        )

    def test_valid_tree(self) -> None:
        result = validate_registry_tree(self.root)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["adapters"], 1)
        self.assertEqual(result["registryId"], "test-registry")
        self.assertEqual(result["sequence"], 1)

    def test_registry_schema_6_rejected(self) -> None:
        self.mutate_registry(lambda value: value.update(schema=6))
        errors = self.errors()
        self.assertTrue(any("schema" in error and "7" in error for error in errors), errors)

    def test_manifest_schema_4_rejected(self) -> None:
        self.update_manifest(lambda manifest: manifest.update(schema=4))
        errors = self.errors()
        self.assertTrue(
            any("manifest schema must be 5" in error for error in errors), errors
        )

    def test_entry_api_version_missing_rejected(self) -> None:
        self.mutate_registry(lambda value: value["adapters"][0].pop("apiVersion"))
        errors = self.errors()
        self.assertTrue(any("apiVersion" in error for error in errors), errors)

    def test_entry_api_version_wrong_rejected(self) -> None:
        self.mutate_registry(
            lambda value: value["adapters"][0].update(apiVersion=1)
        )
        errors = self.errors()
        self.assertTrue(any("apiVersion" in error for error in errors), errors)

    def test_manifest_api_version_missing_rejected(self) -> None:
        self.update_manifest(lambda manifest: manifest.pop("apiVersion"))
        errors = self.errors()
        self.assertTrue(any("manifest apiVersion" in error for error in errors), errors)

    def test_manifest_api_version_wrong_rejected(self) -> None:
        self.update_manifest(lambda manifest: manifest.update(apiVersion=1))
        errors = self.errors()
        self.assertTrue(any("manifest apiVersion" in error for error in errors), errors)

    def test_root_name_rejected(self) -> None:
        self.mutate_registry(lambda value: value.update(name="Test registry"))
        errors = self.errors()
        self.assertTrue(any("root name" in error for error in errors), errors)

    def test_publisher_must_be_string(self) -> None:
        self.mutate_registry(lambda value: value.update(publisher={"name": "x"}))
        self.assertTrue(any("publisher" in error for error in self.errors()))

    def test_files_must_be_objects(self) -> None:
        self.mutate_registry(
            lambda value: value["adapters"][0].update(files=["adapter.lua"])
        )
        self.assertTrue(any("files" in error for error in self.errors()))

    def test_missing_file_hash_rejected(self) -> None:
        def strip_hashes(value):
            for declared in value["adapters"][0]["files"]:
                declared.pop("sha256", None)

        self.mutate_registry(strip_hashes)
        errors = self.errors()
        self.assertTrue(any("needs a lowercase sha256" in error for error in errors), errors)

    def test_uppercase_file_hash_rejected(self) -> None:
        self.mutate_registry(
            lambda value: value["adapters"][0]["files"][0].update(
                sha256=value["adapters"][0]["files"][0]["sha256"].upper()
            )
        )
        errors = self.errors()
        self.assertTrue(any("sha256" in error for error in errors), errors)

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
            {"mise": "2026.11.11"},
            {"mise": "latest", "uv": "0.13.9"},
            {"mise": "2026.11.11", "uv": "latest"},
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
            {"mise": "2026.11.12"},
            {"uv": True},
            {"mise": "latest", "extra": "1.2.3"},
        ):
            with self.subTest(value=value), tempfile.TemporaryDirectory(
                prefix="redpen-bootstrap-test-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.add_managed_runtime()
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
        self.update_manifest(
            lambda manifest: manifest.update({"bootstrap": {"mise": "latest"}})
        )
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
        self.set_bootstrap({"mise": "latest"}, {"mise": "2026.11.11"})
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

    def test_unsupported_bootstrap_pins(self) -> None:
        for value in (
            "1.2.3",
            "v1.2.3",
            "01.2.3",
            "1.2.3-rc.1",
            "latest-but-not",
            "2026.11.10",
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
        self.set_bootstrap({"uv": "0.13.9"})
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
        self.set_bootstrap({"mise": "latest"}, {"mise": "2026.11.11"})
        errors = self.errors()
        self.assertTrue(any("manifest bootstrap" in error for error in errors), errors)

    def test_legacy_permissions_rejected(self) -> None:
        for permission in (
            "environment",
            "files:read",
            "files:write",
            "directories",
        ):
            with self.subTest(permission=permission), tempfile.TemporaryDirectory(
                prefix="redpen-permissions-test-"
            ) as directory:
                root = write_tree(Path(directory))
                self.root = root
                self.set_permissions([permission])
                errors = validate_registry_tree(root)["errors"]
                self.assertTrue(
                    any(
                        "permissions" in error or permission in error
                        for error in errors
                    ),
                    errors,
                )

    def test_legacy_environment_field_rejected(self) -> None:
        self.update_manifest(lambda manifest: manifest.update(environment="PATH"))
        self.mutate_registry(
            lambda registry: registry["adapters"][0].update(environment="PATH")
        )
        errors = self.errors()
        self.assertTrue(any("environment" in error for error in errors), errors)

    def test_mirrored_settings_mismatch(self) -> None:
        self.add_managed_runtime()
        self.mutate_registry(
            lambda registry: registry["adapters"][0]["settings"][0].update(
                label="Different label"
            )
        )
        errors = self.errors()
        self.assertTrue(
            any("manifest settings does not match registry" in error for error in errors),
            errors,
        )

    def test_mirrored_output_mismatch(self) -> None:
        self.mutate_registry(
            lambda registry: registry["adapters"][0]["output"].update(kinds=["diff"])
        )
        errors = self.errors()
        self.assertTrue(
            any("manifest output does not match registry" in error for error in errors),
            errors,
        )

    def test_mirrored_question_input_mismatch(self) -> None:
        self.mutate_registry(
            lambda registry: registry["adapters"][0].update(
                questionInput=[
                    {"key": "answer", "label": "Answer", "type": "text"}
                ]
            )
        )
        errors = self.errors()
        self.assertTrue(
            any(
                "manifest questionInput does not match registry" in error
                for error in errors
            ),
            errors,
        )

    def test_mirrored_directories_mismatch(self) -> None:
        self.mutate_registry(
            lambda registry: registry["adapters"][0].update(directories=["/tmp/data"])
        )
        errors = self.errors()
        self.assertTrue(
            any(
                "manifest directories does not match registry" in error
                for error in errors
            ),
            errors,
        )

    def test_mirrored_directory_picker_mismatch(self) -> None:
        self.mutate_registry(
            lambda registry: registry["adapters"][0].update(
                directoryPicker={"mode": "rw"}
            )
        )
        errors = self.errors()
        self.assertTrue(
            any(
                "manifest directoryPicker does not match registry" in error
                for error in errors
            ),
            errors,
        )

    def test_missing_readme_rejected(self) -> None:
        (self.root / "demo" / "README.md").unlink()
        errors = self.errors()
        self.assertTrue(any("missing README.md" in error for error in errors), errors)

    def test_readme_version_mismatch_rejected(self) -> None:
        (self.root / "demo" / "README.md").write_text(
            "# Demo\n\n- **Version:** 9.9.9\n", encoding="utf-8"
        )
        errors = self.errors()
        self.assertTrue(
            any("README.md version does not match" in error for error in errors),
            errors,
        )

    def test_hash_mismatch_rejected(self) -> None:
        (self.root / "demo" / "adapter.lua").write_text(
            "app.result({ text = 'changed' })\n", encoding="utf-8"
        )
        errors = self.errors()
        self.assertTrue(any("sha256 mismatch" in error for error in errors), errors)

    def test_manifest_id_mismatch_rejected(self) -> None:
        self.update_manifest(lambda manifest: manifest.update(id="other"))
        errors = self.errors()
        self.assertTrue(any("manifest id does not match" in error for error in errors), errors)

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


class PinnedSchemaTests(unittest.TestCase):
    def test_constants_match_v2_contract(self) -> None:
        self.assertEqual(SCHEMA, 7)
        self.assertEqual(MANIFEST_SCHEMA, 5)
        self.assertEqual(API_VERSION, 2)
        registry_schema = load_schema("registry.schema.json")
        manifest_schema = load_schema("manifest.schema.json")
        self.assertEqual(registry_schema["$defs"]["registrySchema"]["const"], 7)
        self.assertEqual(registry_schema["$defs"]["apiVersion"]["const"], 2)
        self.assertEqual(manifest_schema["$defs"]["manifestSchema"]["const"], 5)
        self.assertEqual(manifest_schema["$defs"]["apiVersion"]["const"], 2)

    def test_mirror_fields_are_loaded_from_the_generated_file(self) -> None:
        fields = load_mirror_fields()
        self.assertIn("settings", fields)
        self.assertIn("keyInput", fields)
        self.assertIn("questionInput", fields)
        self.assertIn("output", fields)
        self.assertIn("directories", fields)
        self.assertIn("directoryPicker", fields)
        data = json.loads(
            (ROOT / "redpen_signing" / "schemas" / "mirror-fields.json").read_text()
        )
        self.assertEqual(fields, tuple(data["fields"]))

    def test_copied_files_match_source_manifest(self) -> None:
        schema_dir = ROOT / "redpen_signing" / "schemas"
        source = json.loads((schema_dir / "source.json").read_text())
        self.assertEqual(source["appCommit"], "47a4f83d92f102583ac95048856ec00376d55d3c")
        for name, expected in source["files"].items():
            with self.subTest(name=name):
                digest = hashlib.sha256((schema_dir / name).read_bytes()).hexdigest()
                self.assertEqual(digest, expected)
                self.assertEqual(source["sourcePaths"][name], f"schemas/{name}")


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
