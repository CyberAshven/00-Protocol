# core/contact_card.py
"""Contact card URL encoding/decoding for chat.cash.

URL format:
    chatcash:<bch_address>?pub=<x25519_pub_hex>&name=<url_encoded_name>

Example:
    chatcash:bitcoincash:qp1234...?pub=abcdef01...&name=Alice
"""
from __future__ import annotations

from urllib.parse import urlencode, unquote_plus
from typing import Optional

_SCHEME = "chatcash"


def encode_contact_card(bch_address: str, pub_hex: str, name: str) -> str:
    """Build a chatcash: contact card URL."""
    params = urlencode({"pub": pub_hex, "name": name})
    return f"{_SCHEME}:{bch_address}?{params}"


def decode_contact_card(url: str) -> dict:
    """
    Parse a chatcash: URL.

    Returns dict with keys: bch_address, pub_hex, name.
    Raises ValueError on malformed input.
    """
    url = url.strip()
    if not url.startswith(f"{_SCHEME}:"):
        raise ValueError(f"Not a chatcash: URL: {url!r}")

    rest = url[len(_SCHEME) + 1:]  # strip "chatcash:"
    bch_address, _, query = rest.partition("?")
    bch_address = bch_address.strip()
    if not bch_address:
        raise ValueError("Missing BCH address in contact card URL")

    params: dict = {}
    for part in query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            params[k.strip()] = unquote_plus(v)

    pub_hex = params.get("pub", "").strip()
    name = params.get("name", "").strip() or bch_address[:16]

    if not pub_hex or len(pub_hex) != 64:
        raise ValueError(
            f"Invalid pub_hex (expected 64 hex chars, got {len(pub_hex)})"
        )
    try:
        bytes.fromhex(pub_hex)
    except ValueError:
        raise ValueError("pub_hex contains non-hex characters")

    return {"bch_address": bch_address, "pub_hex": pub_hex, "name": name}


def make_qr_image(url: str):
    """
    Generate a QR code PIL Image for the given URL.
    Returns None if qrcode or PIL is not installed.
    """
    try:
        import qrcode  # type: ignore
        return qrcode.make(url)
    except ImportError:
        return None
