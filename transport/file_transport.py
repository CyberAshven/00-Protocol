import json
import time
import uuid
from pathlib import Path
from typing import Callable, List

from core.watcher import InboxWatcher
from transport.base import Transport


class FileTransport(Transport):
    def __init__(self, net_dir: Path, inbox_id: str):
        self.net_dir = net_dir
        self.inbox_id = inbox_id
        self.inbox_dir = net_dir / "inbox" / inbox_id
        self.watcher = None

    def send_packets(self, dest: str, packets: List[bytes], meta: dict) -> None:
        dest_dir = self.net_dir / "inbox" / dest
        dest_dir.mkdir(parents=True, exist_ok=True)

        msg = {
            "ts": int(time.time()),
            "meta": meta,
            "packets_hex": [p.hex() for p in packets],
        }

        fname = f"msg_{uuid.uuid4().hex}.json"
        (dest_dir / fname).write_text(json.dumps(msg, indent=2))

    def start_listener(self, on_packets: Callable[[List[bytes], dict], None]) -> None:
        def handle(path: Path):
            raw = json.loads(path.read_text())
            packets = [bytes.fromhex(hx) for hx in raw.get("packets_hex", [])]
            meta = raw.get("meta", {})
            on_packets(packets, meta)

            processed = self.inbox_dir / "processed"
            processed.mkdir(exist_ok=True)
            path.rename(processed / path.name)

        self.watcher = InboxWatcher(
            inbox_dir=self.inbox_dir,
            on_event=lambda e: handle(e.path),
            pattern="msg_*.json",
            poll_interval_s=0.5,
            ignore_errors=True,
        )
        self.watcher.start()

    def stop(self) -> None:
        if self.watcher:
            self.watcher.stop()