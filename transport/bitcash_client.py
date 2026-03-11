# transport/bitcash_client.py
"""
Client BCH basé sur l'API Blockchair (REST publique, pas d'auth requise pour un usage modéré)
et la lib bitcash pour le broadcast.

Interface compatible avec EcClient : mêmes méthodes getaddresshistory() et gettransaction_hex_any().

Avantages par rapport à EcClient :
- Pas besoin d'Electron Cash installé localement
- Fonctionne en headless/server
- bitcash gère le broadcast via son propre réseau de nœuds
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    from bitcash.network import NetworkAPI as _BchAPI
    _HAS_BITCASH = True
except ImportError:
    _HAS_BITCASH = False

# Blockchair BCH API — free, no key, rate-limited (~30 req/min sans clé)
_BLOCKCHAIR_BASE = "https://api.blockchair.com/bitcoin-cash"
_BLOCKCHAIR_ADDR = _BLOCKCHAIR_BASE + "/dashboards/address/{}"
_BLOCKCHAIR_TX   = _BLOCKCHAIR_BASE + "/raw/transaction/{}"


@dataclass
class BitcashClient:
    """
    Client réseau BCH sans Electron Cash.

    Usage:
        client = BitcashClient()
        history = client.getaddresshistory("bitcoincash:q...")
        raw_hex = client.gettransaction_hex_any("deadbeef...")
        BitcashClient.broadcast("02000000...")
    """
    timeout: int = 15

    def _req(self) -> Any:
        if not _HAS_REQUESTS:
            raise RuntimeError("requests not installed. pip install requests")
        return _requests

    def getaddresshistory(self, address: str) -> List[Dict[str, Any]]:
        """
        Retourne la liste des transactions pour une adresse BCH.
        Compatible avec EcClient.getaddresshistory() → liste de dicts {tx_hash, height}.
        """
        req = self._req()
        r = req.get(
            _BLOCKCHAIR_ADDR.format(address),
            params={"limit": 100, "offset": 0},
            timeout=self.timeout,
        )
        r.raise_for_status()
        data_map: dict = r.json().get("data", {})

        # Blockchair indexe la clé par l'adresse cashaddr
        entry = (
            data_map.get(address)
            or data_map.get(address.lower())
            or (next(iter(data_map.values()), {}) if data_map else {})
        )
        txids: List[str] = entry.get("transactions", []) if isinstance(entry, dict) else []
        return [{"tx_hash": txid, "height": 0} for txid in txids]

    def gettransaction_hex_any(self, txid: str) -> str:
        """
        Retourne le raw hex d'une transaction BCH.
        Compatible avec EcClient.gettransaction_hex_any().
        """
        req = self._req()
        r = req.get(_BLOCKCHAIR_TX.format(txid), timeout=self.timeout)
        r.raise_for_status()
        inner = r.json().get("data", {}).get(txid, {})
        raw_hex: str = inner.get("raw_transaction", "")
        if not raw_hex:
            raise RuntimeError(f"Blockchair: pas de raw_transaction pour {txid!r}")
        return raw_hex

    @staticmethod
    def broadcast(tx_hex: str) -> None:
        """
        Diffuse une transaction BCH signée sur le réseau.
        Utilise bitcash.network.NetworkAPI.broadcast_tx().
        """
        if not _HAS_BITCASH:
            raise RuntimeError("bitcash not installed. pip install bitcash")
        _BchAPI.broadcast_tx(tx_hex)
