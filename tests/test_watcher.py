import json
import time
from pathlib import Path
import pytest
from core.watcher import InboxWatcher, WatchEvent


def _start(tmp_path, events, pattern="msg_*.json", poll=0.04):
    w = InboxWatcher(tmp_path, on_event=events.append, pattern=pattern, poll_interval_s=poll)
    w.start()
    return w


def _wait(cond, timeout=2.0, step=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def test_detects_new_file(tmp_path: Path):
    events = []
    w = _start(tmp_path, events)
    (tmp_path / "msg_001.json").write_text(json.dumps({"key": "value"}), encoding="utf-8")
    assert _wait(lambda: len(events) == 1), "event not received"
    w.stop()
    assert events[0].payload == {"key": "value"}
    assert isinstance(events[0], WatchEvent)


def test_no_duplicates(tmp_path: Path):
    events = []
    w = _start(tmp_path, events)
    (tmp_path / "msg_dup.json").write_text('{"x":1}')
    _wait(lambda: len(events) >= 1)
    time.sleep(0.2)  # multiple scan cycles
    w.stop()
    assert len(events) == 1


def test_ignores_invalid_json(tmp_path: Path):
    events = []
    w = _start(tmp_path, events)
    (tmp_path / "msg_bad.json").write_text("{{ NOT JSON {{")
    time.sleep(0.3)
    w.stop()
    assert len(events) == 0


def test_ignores_non_matching_pattern(tmp_path: Path):
    events = []
    w = _start(tmp_path, events)
    (tmp_path / "other_file.json").write_text('{"x":1}')
    time.sleep(0.2)
    w.stop()
    assert len(events) == 0


def test_multiple_files(tmp_path: Path):
    events = []
    w = _start(tmp_path, events)
    for i in range(3):
        (tmp_path / f"msg_{i:03d}.json").write_text(json.dumps({"i": i}))
    assert _wait(lambda: len(events) == 3), f"expected 3, got {len(events)}"
    w.stop()
    payloads = {e.payload["i"] for e in events}
    assert payloads == {0, 1, 2}


def test_start_stop_idempotent(tmp_path: Path):
    w = InboxWatcher(tmp_path, on_event=lambda e: None, poll_interval_s=0.1)
    w.start()
    w.start()   # double start safe
    w.stop()
    w.stop()    # double stop safe


def test_creates_inbox_dir(tmp_path: Path):
    events = []
    target = tmp_path / "deep" / "inbox"
    w = InboxWatcher(target, on_event=events.append, poll_interval_s=0.1)
    w.start()
    assert target.exists()
    w.stop()
