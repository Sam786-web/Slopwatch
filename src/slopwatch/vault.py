"""Encryption for sensitive research data (Fernet: AES-128-CBC + HMAC-SHA256, from `cryptography`).

Why: the watchlist holds UNREGISTERED hallucinated package names. Published in plain text it
would be a shopping list for attackers. Encrypting it lets the code repo be public (and
GitHub Pages free) while only holders of SLOPWATCH_KEY (you locally, CI via a GitHub secret)
can read the list.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()
KEY_ENV = "SLOPWATCH_KEY"


class VaultError(RuntimeError):
    pass


def new_key() -> str:
    return Fernet.generate_key().decode()


def _fernet(key: str | None = None) -> Fernet:
    key = key or os.getenv(KEY_ENV)
    if not key:
        raise VaultError(f"{KEY_ENV} is not set (run `slopwatch keygen`, or add the GitHub secret in CI)")
    return Fernet(key.encode())


def has_key() -> bool:
    return bool(os.getenv(KEY_ENV))


def encrypt_bytes(data: bytes, key: str | None = None) -> bytes:
    return _fernet(key).encrypt(data)


def decrypt_bytes(token: bytes, key: str | None = None) -> bytes:
    try:
        return _fernet(key).decrypt(token)
    except InvalidToken as e:
        raise VaultError("wrong SLOPWATCH_KEY or tampered file") from e


def read_text(path: Path, key: str | None = None) -> str:
    """Read a file, decrypting it if it ends in .enc."""
    raw = path.read_bytes()
    return (decrypt_bytes(raw, key) if path.suffix == ".enc" else raw).decode("utf-8")


def write_text(path: Path, text: str, key: str | None = None) -> None:
    """Write a file, encrypting it if it ends in .enc."""
    data = text.encode("utf-8")
    path.write_bytes(encrypt_bytes(data, key) if path.suffix == ".enc" else data)
