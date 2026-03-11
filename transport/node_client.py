# transport/node_client.py
"""NodeClient Protocol — duck-type interface for BCH network clients.

Both EcClient (Electron Cash subprocess) and BitcashClient (Blockchair REST)
satisfy this protocol without modification; no import-time dependency on either.
"""
from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable


@runtime_checkable
class NodeClient(Protocol):
    """Minimal BCH node interface required by BchInboxScanner."""

    def getaddresshistory(self, address: str) -> List[Dict[str, Any]]:
        """Return list of {tx_hash, height} dicts for the given BCH address."""
        ...

    def gettransaction_hex_any(self, txid: str) -> str:
        """Return raw transaction hex for the given txid."""
        ...
