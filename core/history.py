# core/history.py
"""Encrypted message history per contact.

Encryption: AES-256-GCM, key derived from the profile's X25519 private key
via HKDF-SHA256. Each entry is encrypted with a fresh random nonce.

On-disk format (one file per contact):
  - Filename = HMAC-SHA256(history_key, contact_name)[:32].enc
    → hides which contact the file belongs to
  - One line per message: <12-byte-nonce-hex><ciphertext-hex>
  - Plaintext per entry (JSON):
      {"ts": 1710000000.123, "dir": "out"|"in", "contact": "Alice", "text": "hello"}
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

_SALT = b"chat.cash.history.v1"
_INFO = b"history-aes-key"


@dataclass(frozen=True)
class HistoryEntry:
    ts: float
    direction: str   # "out" | "in"
    contact: str
    text: str

    def display_line(self) -> str:
        prefix = "me" if self.direction == "out" else self.contact
        return f"{prefix}: {self.text}"


def _derive_key(priv_hex: str) -> bytes:
    """Derive AES-256 key from X25519 private key hex via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        info=_INFO,
    ).derive(bytes.fromhex(priv_hex))


def _contact_filename(key: bytes, contact: str) -> str:
    """Opaque filename: HMAC-SHA256(key, contact_name)[:32].enc — hides identity."""
    return hmac.new(key, contact.encode("utf-8"), hashlib.sha256).hexdigest()[:32] + ".enc"


class HistoryStore:
    """Encrypted append-only message store, one file per contact."""

    def __init__(self, history_dir: Path, priv_hex: str) -> None:
        self._dir = history_dir
        self._key = _derive_key(priv_hex)
        self._aes = AESGCM(self._key)

    def _path(self, contact: str) -> Path:
        return self._dir / _contact_filename(self._key, contact)

    def _encrypt(self, entry: HistoryEntry) -> str:
        nonce = os.urandom(12)
        pt = json.dumps(
            {"ts": entry.ts, "dir": entry.direction, "contact": entry.contact, "text": entry.text},
            ensure_ascii=False,
        ).encode("utf-8")
        ct = self._aes.encrypt(nonce, pt, None)
        return nonce.hex() + ct.hex()

    def _decrypt(self, line: str) -> HistoryEntry:
        raw = bytes.fromhex(line.strip())
        pt = self._aes.decrypt(raw[:12], raw[12:], None)
        d = json.loads(pt.decode("utf-8"))
        return HistoryEntry(ts=d["ts"], direction=d["dir"], contact=d["contact"], text=d["text"])

    def append(self, contact: str, direction: str, text: str) -> None:
        """Encrypt and append one message entry to the contact's history file."""
        self._dir.mkdir(parents=True, exist_ok=True)
        entry = HistoryEntry(ts=time.time(), direction=direction, contact=contact, text=text)
        with self._path(contact).open("a", encoding="utf-8") as f:
            f.write(self._encrypt(entry) + "\n")

    def load(self, contact: str) -> List[HistoryEntry]:
        """Load and decrypt all entries for a contact, sorted by timestamp."""
        path = self._path(contact)
        if not path.exists():
            return []
        entries: List[HistoryEntry] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(self._decrypt(line))
            except Exception:
                pass  # corrupted / truncated line → skip silently
        return sorted(entries, key=lambda e: e.ts)
