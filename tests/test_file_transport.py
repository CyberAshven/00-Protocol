import time
from pathlib import Path

from transport.file_transport import FileTransport


def test_file_transport_send_and_receive(tmp_path: Path):
    # Arrange
    net_dir = tmp_path / "simnet"
    (net_dir / "inbox" / "alice").mkdir(parents=True, exist_ok=True)
    (net_dir / "inbox" / "bob").mkdir(parents=True, exist_ok=True)

    received = {"packets": None, "meta": None}

    def on_packets(packets, meta):
        received["packets"] = packets
        received["meta"] = meta

    bob_t = FileTransport(net_dir=net_dir, inbox_id="bob")
    bob_t.start_listener(on_packets)

    alice_t = FileTransport(net_dir=net_dir, inbox_id="alice")

    packets = [b"\x01\x02\x03", b"\xaa\xbb"]
    meta = {"from": "alice", "msg_id": "deadbeef"}

    # Act
    alice_t.send_packets(dest="bob", packets=packets, meta=meta)

    # Wait (polling watcher)
    deadline = time.time() + 3.0
    while time.time() < deadline and received["packets"] is None:
        time.sleep(0.05)

    # Cleanup
    bob_t.stop()

    # Assert
    assert received["packets"] == packets
    assert received["meta"]["from"] == "alice"
    assert received["meta"]["msg_id"] == "deadbeef"