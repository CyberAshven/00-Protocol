# core/chunks.py
from __future__ import annotations

from typing import Iterable, List, Sequence, Union


BytesLike = Union[bytes, bytearray, memoryview]


def chunk_bytes(data: BytesLike, max_chunk_size: int) -> List[bytes]:
    """
    Split bytes into fixed-size chunks (last chunk can be smaller).

    Args:
        data: bytes to chunk
        max_chunk_size: max size for each chunk (must be > 0)

    Returns:
        list of bytes chunks
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if not isinstance(max_chunk_size, int) or max_chunk_size <= 0:
        raise ValueError("max_chunk_size must be a positive int")

    b = bytes(data)
    return [b[i:i + max_chunk_size] for i in range(0, len(b), max_chunk_size)]


def rebuild_bytes(chunks: Sequence[BytesLike]) -> bytes:
    """
    Concatenate chunks back into a single bytes object.

    Args:
        chunks: ordered sequence of chunks

    Returns:
        rebuilt bytes
    """
    if chunks is None:
        raise ValueError("chunks must not be None")
    out = bytearray()
    for c in chunks:
        if c is None:
            raise ValueError("chunks contains None (missing piece)")
        if not isinstance(c, (bytes, bytearray, memoryview)):
            raise TypeError("each chunk must be bytes-like")
        out += bytes(c)
    return bytes(out)


def chunk_text_utf8(text: str, max_chunk_size: int) -> List[bytes]:
    """
    Convenience helper: utf-8 encode then chunk.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return chunk_bytes(text.encode("utf-8"), max_chunk_size=max_chunk_size)


def rebuild_text_utf8(chunks: Sequence[BytesLike]) -> str:
    """
    Convenience helper: rebuild then decode utf-8.
    """
    return rebuild_bytes(chunks).decode("utf-8", errors="strict")