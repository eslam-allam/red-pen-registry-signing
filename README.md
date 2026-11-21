# red-pen-registry-signing

Pinned signing and verification code used by Red Pen adapter registry
workflows. This repository is **public** and contains **no private keys and no
secrets**, so registries can check it out by commit SHA without a
cross-repository token. It is pinned at the SHA recorded in a registry's
`registry.config.json`; workflows never execute signing code from the pull
request or commit being signed.

## Why a separate repository

A registry's own workflow file cannot be trusted to sign the change that
modifies it. Pinning a small, reviewed signer implementation by SHA limits the
code that sees `MINISIGN_SECRET_KEY_B64` and `MINISIGN_PASSWORD`.

## What it does

- validates `kind: "red-pen-adapters"`, schema 6, and lowercase slug registry
  ids (official `red-pen-official`, community `red-pen-community`);
- validates entry-level `bootstrap` pins (`mise`/`uv`): only `latest` or a
  semver pin is accepted, and the entry must match the manifest;
- writes deterministic registry bytes (sorted keys, two-space indent, LF, one
  trailing newline);
- bumps `sequence`, sets `issuedAt` and `expiresAt`;
- signs the exact bytes with minisign 0.12 through a password-only PTY wrapper
  (no `-W`, no password in argv, no password or minisign output in logs);
- verifies the signature and the trusted comment
  `registryId=<id> sequence=<n>` immediately after signing;
- verifies exact bytes, canonical form, sequence, expiry, and registry id;
- validates config canonical bytes, keyFile existence/parse, official/community
  environment names, reserved ids, and self-signer rejection;
- skips stale `release.json` with `--skip-release` during pre-signing, then
  checks the fresh release metadata in release mode;
- writes a mode-0700 `GIT_ASKPASS` helper without putting the token in argv;
- prints key IDs and SHA-256 public-key fingerprints;
- writes `release.json` with digests and signer provenance;
- provides a test-key round trip that never touches production secrets.

## Commands

```sh
python -m redpen_signing.cli version
python -m redpen_signing.cli key-id --public-key keys/official-2026.pub
python -m redpen_signing.cli validate --root . --registry registry.json --config registry.config.json --skip-release
python -m redpen_signing.cli validate --root . --registry registry.json --config registry.config.json --require-signature
python -m redpen_signing.cli write-askpass --out "$RUNNER_TEMP/git-askpass.sh" --env GH_TOKEN
python -m redpen_signing.cli ci-config --config registry.config.json
python -m redpen_signing.cli check-pin --repo-dir . --commit <40-char-sha>
python -m redpen_signing.cli install-secret-key --env MINISIGN_SECRET_KEY_B64 --out "$RUNNER_TEMP/minisign.key"
python -m redpen_signing.cli prepare --registry registry.json --config registry.config.json --out "$RUNNER_TEMP/registry.json" --base-sequence 4
python -m redpen_signing.cli sign --registry registry.json --sig registry.json.minisig --secret-key "$RUNNER_TEMP/minisign.key" --public-key keys/official-2026.pub --config registry.config.json
python -m redpen_signing.cli verify --registry registry.json --sig registry.json.minisig --public-key keys/official-2026.pub --config registry.config.json
python -m redpen_signing.cli release --registry registry.json --sig registry.json.minisig --public-key keys/official-2026.pub --config registry.config.json --out release.json --signer-commit "$SIGNER_COMMIT"
python -m redpen_signing.cli test-key --registry registry.json --config registry.config.json
```

`sign` reads the password from `MINISIGN_PASSWORD` (override with
`--password-env`). `install-secret-key` reads base64 from
`MINISIGN_SECRET_KEY_B64`, writes mode `0600`, and never prints the value.

## Requirements

- Python 3.8 or newer; the signing workflow uses 3.13.
- `jsonschema` for full schema-6/tree validation (pinned in `requirements.txt`).
- minisign 0.12, either on `PATH` or via `MINISIGN_BIN`.
- The key must be password-encrypted. `-W` (unencrypted keys) is deliberately
  not used.

## Tests

```sh
MINISIGN_BIN=/path/to/minisign python tests/run.py
```

Crypto tests are skipped when minisign is unavailable; CI installs the pinned
release and runs all of them, including a throwaway encrypted key round trip.

## Key IDs and fingerprints

A minisign public key decodes to 42 bytes: `Ed`, an eight-byte key id, and a
32-byte Ed25519 public key. The authoritative conventions match G1 and
minisign:

- `keyId` is **uppercase**, **byte-reversed** 8-byte minisign id
  (for example `E7A93C572FF84DB5`);
- `fingerprint` is the SHA-256 of the **exact `.pub` file bytes**, including the
  untrusted comment and trailing newline (not the decoded key).

Both are safe to publish. `tests/fixtures/g1-keys` cross-checks these values
against the app's published `src-tauri/keys/README.md` data.

## Security

- No secret key, password, token, or signing environment is stored here.
- The signer workflow runs only with `contents: read`; the registry workflow
  grants write access only to its signing job.
- The PTY wrapper disables echo, discards every byte minisign writes, limits
  password attempts, kills timed-out process groups, and reports only exit
  status.
- Verification is mandatory after signing. A failed verification leaves the
  previous signature untouched.
