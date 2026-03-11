# transport/bch_inbox_scanner.py
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from core.packet_v1 import unpack_packet, PacketV1, MSG_TYPE_ENCRYPTED_CHUNK, MSG_TYPE_ADDR_CHANGE
from core.protocol import decode_packets, DecodedMessage, decode_addr_change_packets, AddrChangeMessage
from transport.node_client import NodeClient


def _read_varint(b: bytes, i: int) -> tuple[int, int]:
    x = b[i]
    if x < 0xFD:
        return x, i + 1
    if x == 0xFD:
        return int.from_bytes(b[i + 1 : i + 3], "little"), i + 3
    if x == 0xFE:
        return int.from_bytes(b[i + 1 : i + 5], "little"), i + 5
    return int.from_bytes(b[i + 1 : i + 9], "little"), i + 9


def _extract_opreturn_datas_with_vout(tx_hex: str) -> List[Tuple[int, bytes]]:
    """
    Parse raw tx hex and return list of (vout_index, pushed_data_bytes) for OP_RETURN outputs.
    """
    b = bytes.fromhex(tx_hex)
    i = 0
    i += 4  # version
    n_in, i = _read_varint(b, i)

    for _ in range(n_in):
        i += 32 + 4  # prev hash + index
        sl, i = _read_varint(b, i)
        i += sl
        i += 4  # sequence

    n_out, i = _read_varint(b, i)
    out: List[Tuple[int, bytes]] = []

    for vout in range(n_out):
        i += 8  # value
        pk_len, i = _read_varint(b, i)
        script = b[i : i + pk_len]
        i += pk_len

        if not script or script[0] != 0x6A:  # OP_RETURN
            continue
        if len(script) < 2:
            continue

        # Only supports single-push OP_RETURN.
        op = script[1]
        j = 2

        if op < 0x4C:
            n = op
        elif op == 0x4C:
            if len(script) < j + 1:
                continue
            n = script[j]
            j += 1
        elif op == 0x4D:
            if len(script) < j + 2:
                continue
            n = script[j] | (script[j + 1] << 8)
            j += 2
        else:
            continue

        if len(script) < j + n:
            continue
        data = script[j : j + n]
        out.append((vout, data))

    return out


@dataclass
class ScannerState:
    # stable dedup entries like:
    #  - "txid:vout" (OP_RETURN output index)
    #  - or "txid:vout:sha256(data)" if you want stronger uniqueness (we do it below)
    seen: Set[str]

    @classmethod
    def load(cls, path: Path) -> "ScannerState":
        if not path.exists():
            return cls(seen=set())
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen=set(d.get("seen", [])))
        except Exception:
            return cls(seen=set())

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"seen": sorted(self.seen)}, indent=2), encoding="utf-8")


class BchInboxScanner:
    """
    Poll EC getaddresshistory + gettransaction, extract OP_RETURN CCSH packets, reassemble per msg_id,
    decrypt (decode_packets), call on_message(decoded_message).
    """

    def __init__(
        self,
        *,
        ec: NodeClient,
        address: str,
        recipient_priv_hex: str,
        state_path: Path,
        poll_s: float = 6.0,
        on_message: Callable[[DecodedMessage, dict], None],
        on_addr_change: Optional[Callable[[AddrChangeMessage, dict], None]] = None,
        magic: bytes = b"CCSH",
        # safety / robustness
        bucket_ttl_s: float = 10 * 60,   # purge partial messages after 10min
        max_buckets: int = 2048,         # avoid unbounded memory
        save_every_s: float = 5.0,       # rate limit disk writes
    ):
        self.ec = ec
        self.address = address
        self.recipient_priv_hex = recipient_priv_hex
        self.state_path = state_path
        self.poll_s = poll_s
        self.on_message = on_message
        self.on_addr_change = on_addr_change
        self.magic = magic

        self.bucket_ttl_s = bucket_ttl_s
        self.max_buckets = max_buckets
        self.save_every_s = save_every_s

        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None

        self.state = ScannerState.load(self.state_path)
        self._dirty_state = False
        self._last_save_ts = 0.0

        # msg_id -> (created_ts, chunk_total, msg_type, {chunk_index: raw_packet_bytes})
        self._buckets: Dict[bytes, Tuple[float, int, int, Dict[int, bytes]]] = {}

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        self._th = threading.Thread(target=self._run, name="BchInboxScanner", daemon=True)
        self._th.start()

    def stop(self) -> None:
        self._stop.set()
        th = self._th
        if th and th.is_alive():
            th.join(timeout=2.0)

        # last flush
        try:
            self._save_state(force=True)
        except Exception:
            pass

    def _run(self) -> None:
        # loop with interruptible wait
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception:
                # silent by design (UI owns status)
                pass

            # interruptible sleep
            self._stop.wait(self.poll_s)

    def _save_state(self, force: bool = False) -> None:
        now = time.time()
        if not force:
            if not self._dirty_state:
                return
            if (now - self._last_save_ts) < self.save_every_s:
                return

        self.state.save(self.state_path)
        self._dirty_state = False
        self._last_save_ts = now

    def _purge_buckets(self) -> None:
        if not self._buckets:
            return

        now = time.time()
        # TTL purge
        expired = [mid for mid, (ts, _tot, _mtype, _chunks) in self._buckets.items() if (now - ts) > self.bucket_ttl_s]
        for mid in expired:
            self._buckets.pop(mid, None)

        # hard cap purge (oldest first)
        if len(self._buckets) > self.max_buckets:
            items = sorted(self._buckets.items(), key=lambda kv: kv[1][0])  # sort by created_ts
            for mid, _ in items[: max(0, len(self._buckets) - self.max_buckets)]:
                self._buckets.pop(mid, None)

    def _poll_once(self) -> None:
        self._purge_buckets()

        hist = self.ec.getaddresshistory(self.address)

        # Usually oldest->newest or vice versa depending server;
        # we don't assume — just iterate all, dedup handles repeats.
        for h in hist:
            if self._stop.is_set():
                return

            txid = h.get("tx_hash") or h.get("txid") or h.get("hash")
            if not txid:
                continue

            try:
                tx_hex = self.ec.gettransaction_hex_any(txid)
            except Exception:
                continue  # tx not reachable yet (server, mempool, etc.)
            opret = _extract_opreturn_datas_with_vout(tx_hex)

            for vout, data in opret:
                if not data.startswith(self.magic):
                    continue

                # stronger key: txid:vout:sha256(data)
                dh = hashlib.sha256(data).hexdigest()[:16]
                key = f"{txid}:{vout}:{dh}"
                if key in self.state.seen:
                    continue

                self.state.seen.add(key)
                self._dirty_state = True

                # data is a packed packet (CCSH...)
                raw_pkt = data
                pkt: PacketV1 = unpack_packet(raw_pkt)

                self._bucket_packet(txid, vout, pkt, raw_pkt)

        self._save_state(force=False)

    def _bucket_packet(self, txid: str, vout_index: int, pkt: PacketV1, raw_pkt: bytes) -> None:
        msg_id = pkt.msg_id
        total = pkt.chunk_total
        msg_type = pkt.msg_type

        created_ts, cur_total, cur_type, chunk_map = self._buckets.get(
            msg_id, (time.time(), total, msg_type, {})
        )
        if cur_total != total:
            # inconsistent => reset bucket
            self._buckets[msg_id] = (time.time(), total, msg_type, {pkt.chunk_index: raw_pkt})
            return

        # dedup by chunk index
        if pkt.chunk_index in chunk_map:
            return

        chunk_map[pkt.chunk_index] = raw_pkt
        self._buckets[msg_id] = (created_ts, total, cur_type, chunk_map)

        if len(chunk_map) < total:
            return

        # complete -> dispatch by msg_type
        packet_list = [chunk_map[i] for i in sorted(chunk_map.keys())]
        meta = {"txid": txid, "vout": vout_index}

        if cur_type == MSG_TYPE_ENCRYPTED_CHUNK:
            decoded = decode_packets(packet_list, recipient_priv_hex=self.recipient_priv_hex)
            for m in decoded:
                self.on_message(m, {**meta, "msg_id": m.msg_id})

        elif cur_type == MSG_TYPE_ADDR_CHANGE and self.on_addr_change:
            changes = decode_addr_change_packets(packet_list, self.recipient_priv_hex)
            for c in changes:
                self.on_addr_change(c, {**meta, "msg_id": c.msg_id})

        # cleanup
        self._buckets.pop(msg_id, None)