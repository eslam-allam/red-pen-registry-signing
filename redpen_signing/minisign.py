"""Run minisign with a password without exposing the password.

minisign 0.12 encrypts secret keys with a password and reads that password
from a terminal. The only safe automated route is a pseudo-terminal:

* the password comes from the process environment, never argv or a file;
* terminal ECHO is disabled before minisign starts;
* every byte minisign writes to the PTY is discarded, because some versions
  echo KDF or password material when the input is a PTY;
* a timed-out child is killed as a process group.

Only sanitised status messages ever leave this module.
"""

from __future__ import annotations

import os
import pty
import select
import shutil
import signal
import subprocess
import termios
import time
from pathlib import Path
from typing import Optional, Sequence, Union

PathLike = Union[str, "os.PathLike[str]"]

DEFAULT_TIMEOUT = 300
PROMPT_LIMIT = 2
MAX_PASSWORD_BYTES = 1024


class MinisignError(RuntimeError):
    """A minisign operation failed. The message never contains secrets."""


class MinisignNotFound(MinisignError):
    pass


def find_minisign(explicit: Optional[str] = None) -> str:
    candidate = explicit or os.environ.get("MINISIGN_BIN") or shutil.which("minisign")
    if not candidate:
        raise MinisignNotFound(
            "minisign was not found; install minisign 0.12 or set MINISIGN_BIN"
        )
    path = Path(candidate)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise MinisignNotFound(f"minisign binary is not executable: {candidate}")
    return str(path)


def minisign_version(binary: Optional[str] = None) -> str:
    result = subprocess.run(
        [find_minisign(binary), "-v"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env=_safe_environment(),
    )
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else "unknown"


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise MinisignError("an empty minisign password is not allowed")
    if "\n" in password or "\r" in password or "\x00" in password:
        raise MinisignError("the minisign password contains a forbidden character")
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise MinisignError("the minisign password is too long")
    return encoded


def _run_pty(
    command: Sequence[str],
    password: str,
    *,
    prompts: int,
    timeout: int,
) -> int:
    """Run ``command`` on a PTY and answer password prompts.

    The PTY output is used only to detect prompts and is then discarded. It is
    never written to stdout/stderr or included in exceptions.
    """

    master_fd, slave_fd = pty.openpty()
    try:
        attributes = termios.tcgetattr(slave_fd)
        # Disable input echo and the echo-related control characters.
        attributes[3] &= ~(
            termios.ECHO | termios.ECHOE | termios.ECHOK | termios.ECHONL
        )
        termios.tcsetattr(slave_fd, termios.TCSANOW, attributes)

        process = subprocess.Popen(
            list(command),
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            start_new_session=True,
            env=_safe_environment(),
        )
    except BaseException:
        os.close(master_fd)
        os.close(slave_fd)
        raise

    os.close(slave_fd)
    sent = 0
    pending = b""
    deadline = time.monotonic() + timeout
    try:
        while True:
            if process.poll() is not None:
                _drain(master_fd)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_group(process)
                raise MinisignError(f"minisign timed out after {timeout}s")

            ready, _, _ = select.select([master_fd], [], [], min(0.25, remaining))
            if not ready:
                continue
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break

            # Keep only a short rolling window; the full output is discarded.
            pending = (pending + chunk.lower())[-512:]
            if sent < prompts and _is_prompt(pending):
                os.write(master_fd, _password_bytes(password) + b"\n")
                sent += 1
                pending = b""
                # Give minisign a moment to move to the next prompt or exit.
                time.sleep(0.05)

        code = process.wait(timeout=5)
    except BaseException:
        if process.poll() is None:
            _kill_group(process)
        raise
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    if code != 0:
        # Do not include captured PTY output: it can contain secret material.
        raise MinisignError(f"minisign exited with status {code}")
    if sent == 0:
        raise MinisignError(
            "minisign did not ask for a password; the secret key may be "
            "unencrypted or the prompt was not recognised"
        )
    return code


def _is_prompt(window: bytes) -> bool:
    return b"password" in window or b"passphrase" in window


def _drain(fd: int) -> None:
    while True:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            return
        try:
            if not os.read(fd, 4096):
                return
        except OSError:
            return


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        pass


def _safe_environment() -> dict[str, str]:
    """Keep the child environment small and free of unrelated secrets."""

    keep = ("PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "TZ")
    return {name: os.environ[name] for name in keep if name in os.environ}


def generate_key(
    secret_key_path: PathLike,
    public_key_path: PathLike,
    password: str,
    *,
    force: bool = False,
    binary: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    secret = Path(secret_key_path)
    public = Path(public_key_path)
    if secret.exists() and not force:
        raise MinisignError(f"secret key already exists: {secret}")
    if public.exists() and not force:
        raise MinisignError(f"public key already exists: {public}")
    secret.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    command = [find_minisign(binary), "-G", "-p", str(public), "-s", str(secret)]
    if force:
        command.insert(2, "-f")
    _run_pty(command, password, prompts=2, timeout=timeout)
    try:
        os.chmod(secret, 0o600)
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise MinisignError("minisign did not create the secret key") from exc
    if not public.is_file():
        raise MinisignError("minisign did not create the public key")


def sign_file(
    secret_key_path: PathLike,
    message_path: PathLike,
    signature_path: PathLike,
    trusted_comment: str,
    password: str,
    *,
    binary: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> None:
    if not _safe_comment(trusted_comment):
        raise MinisignError("the trusted comment contains a forbidden character")
    message = Path(message_path)
    if not message.is_file():
        raise MinisignError(f"message does not exist: {message}")
    signature = Path(signature_path)
    signature.parent.mkdir(parents=True, exist_ok=True)
    command = [
        find_minisign(binary),
        "-S",
        "-q",
        "-s",
        str(secret_key_path),
        "-m",
        str(message),
        "-x",
        str(signature),
        "-t",
        trusted_comment,
    ]
    _run_pty(command, password, prompts=1, timeout=timeout)
    if not signature.is_file() or signature.stat().st_size == 0:
        raise MinisignError("minisign did not write a signature")


def verify_file(
    public_key_path: PathLike,
    message_path: PathLike,
    signature_path: PathLike,
    *,
    binary: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """Verify a detached signature. Returns False instead of raising."""

    result = subprocess.run(
        [
            find_minisign(binary),
            "-V",
            "-q",
            "-p",
            str(public_key_path),
            "-m",
            str(message_path),
            "-x",
            str(signature_path),
        ],
        check=False,
        capture_output=True,
        timeout=timeout,
        env=_safe_environment(),
    )
    return result.returncode == 0


def _safe_comment(comment: str) -> bool:
    return (
        isinstance(comment, str)
        and 0 < len(comment) <= 1024
        and "\n" not in comment
        and "\r" not in comment
        and "\x00" not in comment
    )
