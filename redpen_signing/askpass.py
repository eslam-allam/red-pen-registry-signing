"""Create a short-lived GIT_ASKPASS helper without putting a token in argv."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Union

from .canonical import atomic_write

PathLike = Union[str, "os.PathLike[str]"]


class AskpassError(ValueError):
    pass


def write_askpass(path: PathLike, token: str) -> Path:
    if not isinstance(token, str) or not token.strip():
        raise AskpassError("the git token is empty")
    if any(character in token for character in ("\n", "\r", "\x00")):
        raise AskpassError("the git token contains a forbidden character")
    quoted = shlex.quote(token)
    script = (
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  *Username*) printf '%s\\n' 'x-access-token' ;;\n"
        f"  *Password*) printf '%s\\n' {quoted} ;;\n"
        "esac\n"
    )
    target = Path(path)
    atomic_write(target, script.encode("utf-8"), mode=0o700)
    os.chmod(target, 0o700)
    return target
