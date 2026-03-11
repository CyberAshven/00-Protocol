# transport/ec_client.py
from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class EcClient:
    ec_path: str
    wallet_path: Optional[str] = None

    def _cmd(self, *args: str) -> List[str]:
        cmd = [self.ec_path]
        if self.wallet_path:
            cmd += ["-w", self.wallet_path]
        cmd += list(args)
        return cmd

    def call_text(self, *args: str) -> str:
        """
        Run Electron Cash CLI and return stdout+stderr as text.
        We don't want stack traces printed to terminal without context.
        """
        p = subprocess.run(
            self._cmd(*args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out = (p.stdout or "").strip()
        if p.returncode != 0:
            raise RuntimeError(f"EC command failed ({p.returncode}): {' '.join(args)}\n{out}")
        return out

    def call_obj(self, *args: str) -> Any:
        """
        Electron Cash CLI output often looks like JSON but may be polluted by warnings.
        We extract the last {...} or [...] or "..." block and parse it safely.
        """
        out = self.call_text(*args)

        # pick last JSON-ish object/array/string in output (robust to warnings above)
        m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\]|\"[\s\S]*\")\s*$", out)
        if not m:
            raise RuntimeError(f"EC returned non structured output:\n{out[:1200]}")

        s = m.group(1)

        # normalize json booleans/null -> python literals
        s = re.sub(r"\btrue\b", "True", s)
        s = re.sub(r"\bfalse\b", "False", s)
        s = re.sub(r"\bnull\b", "None", s)

        return ast.literal_eval(s)

    def getaddresshistory(self, address: str) -> List[Dict[str, Any]]:
        obj = self.call_obj("getaddresshistory", address)
        if not isinstance(obj, list):
            raise RuntimeError(f"Unexpected history type: {type(obj)}")
        return obj  # type: ignore[return-value]

    def gettransaction_hex(self, txid: str) -> str:
        """
        Wallet-context gettransaction (may fail if tx isn't in wallet).
        """
        obj = self.call_obj("gettransaction", txid)
        if not isinstance(obj, dict) or "hex" not in obj:
            raise RuntimeError("gettransaction did not return dict with 'hex'")
        tx_hex = obj.get("hex") or ""
        if not isinstance(tx_hex, str) or not tx_hex:
            raise RuntimeError("empty tx hex")
        return tx_hex

    def gettransaction_hex_any(self, txid: str) -> str:
        """
        Best-effort tx hex fetch:
          1) gettransaction (wallet)
          2) electrum call: blockchain.transaction.get (verbose True)
          3) electrum call: blockchain.transaction.get (verbose False)
        Works with Fulcrum/ElectrumX *if* EC is connected.
        """
        # 1) wallet path
        try:
            return self.gettransaction_hex(txid)
        except Exception:
            pass

        # 2) electrum protocol via EC "get"
        # verbose=True often returns dict { "hex": "...", ... }
        try:
            obj = self.call_obj("get", "blockchain.transaction.get", txid, "true")
            if isinstance(obj, dict) and isinstance(obj.get("hex"), str) and obj["hex"]:
                return obj["hex"]
            if isinstance(obj, str) and obj:
                return obj
        except Exception:
            pass

        # 3) verbose=False often returns raw hex string directly
        obj2 = self.call_obj("get", "blockchain.transaction.get", txid, "false")
        if isinstance(obj2, str) and obj2:
            return obj2
        if isinstance(obj2, dict) and isinstance(obj2.get("hex"), str) and obj2["hex"]:
            return obj2["hex"]

        raise RuntimeError("Unable to fetch tx hex (wallet + electrum fallbacks failed)")