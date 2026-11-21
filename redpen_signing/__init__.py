"""Pinned signing and verification helpers for Red Pen adapter registries.

This package never contains private keys. Registry workflows check out this
repository at a commit SHA recorded in the registry's ``registry.config.json``
and use it to validate, sign, and verify the exact bytes of ``registry.json``.
"""

__version__ = "2.0.0"
