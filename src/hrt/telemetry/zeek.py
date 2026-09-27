"""Zeek conn.log (JSON lines) -> :class:`~hrt.models.Flow`.

Zeek's ``history`` field records TCP control events: upper case means the originator sent
them, lower case the responder (S = SYN, h = SYN-ACK, A = pure ACK, D = data, R = reset).
From it we get the SYN / ACK accounting that the slides' half-open ratio
``TCP SYN_in / TCP ACK_out`` needs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from hrt.models import Flow

REJECT_STATES = {"REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def _num(value, cast=float, default=0):
    try:
        return cast(value) if value not in (None, "-", "") else default
    except (TypeError, ValueError):
        return default


def parse_conn_record(rec: dict) -> Flow | None:
    try:
        src, dst = rec["id.orig_h"], rec["id.resp_h"]
    except KeyError:
        return None
    if ":" in src or ":" in dst:  # the lab is IPv4-only
        return None
    history = rec.get("history") or ""
    proto = (rec.get("proto") or "").lower()
    handshake_done = "h" in history and ("A" in history or "D" in history)
    return Flow(
        ts=_num(rec.get("ts"), float, 0.0),
        src_ip=src,
        src_port=_num(rec.get("id.orig_p"), int, 0),
        dst_ip=dst,
        dst_port=_num(rec.get("id.resp_p"), int, 0),
        proto=proto,
        duration=_num(rec.get("duration"), float, 0.0),
        fwd_bytes=_num(rec.get("orig_bytes"), int, 0),
        bwd_bytes=_num(rec.get("resp_bytes"), int, 0),
        fwd_pkts=_num(rec.get("orig_pkts"), int, 0),
        bwd_pkts=_num(rec.get("resp_pkts"), int, 0),
        syn=proto == "tcp" and "S" in history,
        ack=proto == "tcp" and handshake_done,
        rst="R" in history or "r" in history,
        conn_state=rec.get("conn_state") or "",
    )


def parse_line(line: str) -> Flow | None:
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        return parse_conn_record(json.loads(line))
    except json.JSONDecodeError:
        return None


def read_conn_log(path: Path) -> list[Flow]:
    flows: list[Flow] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            flow = parse_line(line)
            if flow is not None:
                flows.append(flow)
    return flows


class ConnLogTailer:
    """Incrementally reads complete new lines; survives truncation and file replacement."""

    def __init__(self, path: Path, from_start: bool = False):
        self.path = Path(path)
        self._fh = None
        self._ino = None
        self._buf = ""
        self._from_start = from_start
        self.bytes_read = 0

    def _open(self) -> bool:
        if not self.path.exists():
            return False
        self._fh = open(self.path, encoding="utf-8", errors="replace", newline="")
        self._ino = os.stat(self.path).st_ino
        if not self._from_start:
            self._fh.seek(0, os.SEEK_END)
        self._from_start = True  # after the first open, always read reopened files from the start
        return True

    def poll(self) -> list[Flow]:
        if self._fh is None and not self._open():
            return []
        try:
            st = os.stat(self.path)
            if st.st_ino != self._ino or st.st_size < self._fh.tell():
                self._fh.close()
                self._fh, self._buf = None, ""
                if not self._open():
                    return []
        except FileNotFoundError:
            return []
        chunk = self._fh.read()
        if not chunk:
            return []
        self.bytes_read += len(chunk.encode("utf-8", errors="replace"))
        data = self._buf + chunk
        lines = data.split("\n")
        self._buf = lines.pop()  # keep a partial trailing line for the next poll
        return [f for f in (parse_line(ln) for ln in lines) if f is not None]

    def close(self) -> None:
        if self._fh:
            self._fh.close()
