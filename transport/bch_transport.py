# transport/bch_transport.py
from __future__ import annotations

from dataclasses import dataclass
from typing import List

# BCH "nulldata" script: OP_RETURN + pushdata(data)
OP_RETURN = 0x6A
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D


def _pushdata(data: bytes) -> bytes:
    """Return canonical pushdata for the given bytes."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2, n & 0xFF, (n >> 8) & 0xFF]) + data
    raise ValueError("pushdata too large")


def opreturn_script(data: bytes) -> bytes:
    """Build a standard nulldata locking script."""
    return bytes([OP_RETURN]) + _pushdata(data)


def opreturn_script_hex(data: bytes) -> str:
    return opreturn_script(data).hex()


@dataclass(frozen=True)
class OpReturnOutput:
    script_hex: str   # full script, hex (starts with 6a...)
    data_hex: str     # raw data only (your CCSH packet)
    size: int         # raw data size in bytes


class BchTransport:
    """
    Mode B (propre) : on génère
      - une ligne PayToMany (adresse + amount)
      - ET un script OP_RETURN hex brut à coller dans le champ OP_RETURN (case "Script hex brut")
    """

    MAX_OPRETURN_DATA = 220

    @classmethod
    def assert_packets_fit(cls, packets: List[bytes]) -> None:
        too_big = [(i, len(p)) for i, p in enumerate(packets) if len(p) > cls.MAX_OPRETURN_DATA]
        if too_big:
            ex = ", ".join([f"#{i}={n}" for i, n in too_big[:5]])
            raise ValueError(
                f"Some packets exceed OP_RETURN data limit {cls.MAX_OPRETURN_DATA} bytes: {ex}. "
                f"Fix: reduce protocol max_chunk_size so packet <= {cls.MAX_OPRETURN_DATA}."
            )

    @classmethod
    def packets_to_opreturn_outputs(cls, packets: List[bytes]) -> List[OpReturnOutput]:
        cls.assert_packets_fit(packets)
        outs: List[OpReturnOutput] = []
        for p in packets:
            outs.append(
                OpReturnOutput(
                    script_hex=opreturn_script_hex(p),  # <-- 6a...
                    data_hex=p.hex(),
                    size=len(p),
                )
            )
        return outs

    @staticmethod
    def _sats_to_bch_str(sats: int) -> str:
        # 546 -> "0.00000546"
        return f"{sats / 100_000_000:.8f}"

    @classmethod
    def build_payto_lines_for_message(
        cls,
        packets: List[bytes],
        recipient_bch_address: str,
        dust_sats: int = 546,
    ) -> List[str]:
        """
        IMPORTANT:
        - Ce fichier sert UNIQUEMENT au champ PayTo/PayToMany.
        - On n’y met PAS OP_RETURN (EC n’accepte pas ta syntaxe actuelle)
        - On met juste: address,amount
        """
        if not recipient_bch_address:
            raise ValueError("recipient_bch_address is empty")

        # packets not used here, but we keep signature to match caller logic
        amount = cls._sats_to_bch_str(dust_sats)
        return [f"{recipient_bch_address}, {amount}"]

    @classmethod
    def build_opreturn_script_hex_for_message(cls, packets: List[bytes]) -> str:
        """
        Electron Cash (champ OP_RETURN) ajoute déjà OP_RETURN (0x6a).
        Donc si tu coches "Script hex brut", tu dois fournir uniquement le pushdata,
        PAS le 6a initial.
        Résultat attendu côté EC : OP_RETURN, OP_PUSHDATA1 (ou PUSHDATA2)
        """
        outs = cls.packets_to_opreturn_outputs(packets)
        if len(outs) != 1:
            raise ValueError(
                f"Message requires {len(outs)} OP_RETURN outputs. "
                "Electron Cash GUI OP_RETURN field supports only ONE output per tx."
            )

        data = bytes.fromhex(outs[0].data_hex)
        # retourne seulement le pushdata (ex: 4c8d....) sans le 6a
        return _pushdata(data).hex()