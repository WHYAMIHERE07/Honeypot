"""
Honeypot V6 – analysis (JSON output)

Default behaviour:
- Scans for `honeypot_*_v6.db` in the current directory.
- Scans for PCAPs in `./pcap/` named `{FLAVOR}_YYYYMMDD_HHMMSS.pcap`.
- Links each DB to the closest PCAP (by timestamp).
- Outputs one JSON report to stdout.

DB schema assumed:
attacks(id, flavor, timestamp, port, src_port, ip, event_type,
        payload, payload_decoded, payload_encoding, response_sent)
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

DB_GLOB = "honeypot_*_v6.db"
DEFAULT_PCAP_DIR = "pcap"
VALID_FLAVORS = ("CONTROL", "WORDPRESS", "HEALTHCARE")
PCAP_RE = re.compile(r"^(CONTROL|WORDPRESS|HEALTHCARE)_(\d{8})_(\d{6})\.pcap$", re.IGNORECASE)


def _iso(ts: Optional[dt.datetime]) -> Optional[str]:
    return ts.isoformat() if ts else None


def parse_db_flavor(db_path: str) -> Optional[str]:
    name = Path(db_path).name.lower()
    m = re.match(r"^honeypot_(control|wordpress|healthcare)_v6\.db$", name)
    if not m:
        return None
    return m.group(1).upper()


@dataclass(frozen=True)
class PcapInfo:
    path: str
    flavor: str
    start_time: dt.datetime


def discover_pcaps(pcap_dir: str) -> list[PcapInfo]:
    out: list[PcapInfo] = []
    p = Path(pcap_dir)
    if not p.exists():
        return out
    for f in p.glob("*.pcap"):
        m = PCAP_RE.match(f.name)
        if not m:
            continue
        flavor = m.group(1).upper()
        ymd = m.group(2)
        hms = m.group(3)
        start_time = dt.datetime.strptime(ymd + hms, "%Y%m%d%H%M%S")
        out.append(PcapInfo(path=str(f), flavor=flavor, start_time=start_time))
    return sorted(out, key=lambda x: x.start_time)


def get_db_paths(positional: list[str] | None) -> list[str]:
    if positional:
        return [p for p in positional if os.path.isfile(p)]
    return sorted(glob.glob(DB_GLOB))


def get_db_anchor(conn: sqlite3.Connection) -> tuple[Optional[dt.datetime], Optional[int], str]:
    """
    Returns (anchor_time, anchor_id, anchor_source).
    - Prefer STARTUP row (best for time-to-first-probe).
    - Fallback to first recorded event.
    """
    cur = conn.execute(
        "SELECT id, timestamp FROM attacks WHERE event_type='STARTUP' ORDER BY id ASC LIMIT 1"
    )
    row = cur.fetchone()
    if row and row[1]:
        try:
            return dt.datetime.fromisoformat(row[1]), int(row[0]), "STARTUP"
        except Exception:
            pass

    cur = conn.execute("SELECT id, timestamp FROM attacks ORDER BY id ASC LIMIT 1")
    row = cur.fetchone()
    if row and row[1]:
        try:
            return dt.datetime.fromisoformat(row[1]), int(row[0]), "FIRST_EVENT"
        except Exception:
            return None, None, "NONE"
    return None, None, "NONE"


def time_to_first_events(
    conn: sqlite3.Connection,
    anchor: dt.datetime,
    anchor_id: Optional[int],
    end_id: Optional[int] = None,
) -> dict[str, Optional[float] | Optional[str]]:
    def _first_ts_after(event_type: str) -> Optional[dt.datetime]:
        if anchor_id is not None:
            if end_id is not None:
                cur = conn.execute(
                    "SELECT timestamp FROM attacks WHERE event_type=? AND id>? AND id<=? ORDER BY id ASC LIMIT 1",
                    (event_type, anchor_id, end_id),
                )
            else:
                cur = conn.execute(
                    "SELECT timestamp FROM attacks WHERE event_type=? AND id>? ORDER BY id ASC LIMIT 1",
                    (event_type, anchor_id),
                )
        else:
            cur = conn.execute(
                "SELECT timestamp FROM attacks WHERE event_type=? AND timestamp>=? ORDER BY id ASC LIMIT 1",
                (event_type, anchor.isoformat()),
            )
        r = cur.fetchone()
        if not r or not r[0]:
            return None
        try:
            return dt.datetime.fromisoformat(r[0])
        except Exception:
            return None

    syn_ts = _first_ts_after("SYN_SEEN")
    conn_ts = _first_ts_after("CONNECTION_ESTABLISHED")

    def _delta_seconds(t: Optional[dt.datetime]) -> Optional[float]:
        if not t:
            return None
        return max(0.0, (t - anchor).total_seconds())

    return {
        "time_to_first_syn_seen_seconds": _delta_seconds(syn_ts),
        "time_to_first_connection_established_seconds": _delta_seconds(conn_ts),
        "first_syn_seen_at": _iso(syn_ts),
        "first_connection_established_at": _iso(conn_ts),
    }


def db_metrics(conn: sqlite3.Connection, start_id: Optional[int] = None, end_id: Optional[int] = None) -> dict[str, Any]:
    where = ""
    params: tuple[Any, ...] = ()
    if start_id is not None and end_id is not None:
        where = "WHERE id>=? AND id<=?"
        params = (start_id, end_id)

    cur = conn.execute(f"SELECT COUNT(*), COUNT(DISTINCT ip) FROM attacks {where}", params)
    total, unique_ips = cur.fetchone()
    cur = conn.execute(
        f"SELECT event_type, COUNT(*) FROM attacks {where} GROUP BY event_type ORDER BY 2 DESC",
        params,
    )
    by_event = {r[0]: r[1] for r in cur.fetchall()}
    cur = conn.execute(
        f"SELECT ip, COUNT(*) as n FROM attacks {where} GROUP BY ip ORDER BY n DESC LIMIT 10",
        params,
    )
    top_ips = [{"ip": r[0], "events": r[1]} for r in cur.fetchall()]
    return {
        "total_events": int(total or 0),
        "unique_ips": int(unique_ips or 0),
        "by_event_type": by_event,
        "top_ips": top_ips,
    }


def match_closest_pcap(pcaps: list[PcapInfo], flavor: str, anchor: dt.datetime, threshold_minutes: int) -> Optional[dict[str, Any]]:
    candidates = [p for p in pcaps if p.flavor == flavor]
    if not candidates:
        return None
    best = min(candidates, key=lambda p: abs((p.start_time - anchor).total_seconds()))
    diff_sec = abs((best.start_time - anchor).total_seconds())
    if diff_sec > threshold_minutes * 60:
        return None
    return {
        "path": best.path,
        "flavor": best.flavor,
        "pcap_start_time_from_filename": _iso(best.start_time),
        "abs_time_diff_seconds": diff_sec,
    }


def list_run_windows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """
    Split a DB into multiple run windows using STARTUP markers.
    Each run window is [startup_id .. next_startup_id-1] (or until DB end).
    """
    cur = conn.execute(
        "SELECT id, timestamp, payload FROM attacks WHERE event_type='STARTUP' ORDER BY id ASC"
    )
    startups = cur.fetchall()
    if not startups:
        return []

    cur = conn.execute("SELECT MAX(id) FROM attacks")
    max_id = cur.fetchone()[0] or 0

    windows: list[dict[str, Any]] = []
    for i, (sid, sts, spayload) in enumerate(startups):
        next_sid = startups[i + 1][0] if i + 1 < len(startups) else None
        end_id = (next_sid - 1) if next_sid else int(max_id)
        # Attempt to find a SHUTDOWN inside the window (optional)
        cur = conn.execute(
            "SELECT id, timestamp, payload FROM attacks WHERE event_type='SHUTDOWN' AND id>? AND id<=? ORDER BY id ASC LIMIT 1",
            (sid, end_id),
        )
        shut = cur.fetchone()
        windows.append(
            {
                "startup_id": int(sid),
                "startup_time": sts,
                "startup_payload": spayload,
                "end_id": int(end_id),
                "shutdown_id": int(shut[0]) if shut else None,
                "shutdown_time": shut[1] if shut else None,
                "shutdown_payload": shut[2] if shut else None,
            }
        )
    return windows


def tshark_available() -> Optional[str]:
    exe = shutil.which("tshark")
    return exe


def _tshark_frames_count(pcap_path: str) -> Optional[int]:
    # `-z io,stat,0` prints a summary row including frames; we parse the first integer in the data row.
    # Example (varies by version), so keep parsing conservative.
    proc = subprocess.run(
        ["tshark", "-r", pcap_path, "-q", "-z", "io,stat,0"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        return None
    text_out = proc.stdout.splitlines()
    # Find the row that contains frames/packets column. Typically has something like: "|   0 <> 0 | 123 | ..."
    for line in text_out:
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        # heuristic: a stats row often starts with an interval token containing "<>"
        if not parts:
            continue
        if "<>" in parts[0] or parts[0].startswith("0") or parts[0].startswith("Dur"):
            # Look for first numeric token in remaining columns
            for tok in parts[1:]:
                if tok.isdigit():
                    return int(tok)
    return None


def _tshark_syn_to_ports_count(pcap_path: str, ports: list[int]) -> Optional[int]:
    port_expr = " || ".join([f"tcp.dstport=={p}" for p in ports])
    display = f"tcp.flags.syn==1 && tcp.flags.ack==0 && ({port_expr})"
    proc = subprocess.run(
        ["tshark", "-r", pcap_path, "-Y", display, "-q", "-z", "io,stat,0"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        return None
    # Parse frames from output; reuse same parser
    for line in proc.stdout.splitlines():
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|") if p.strip()]
        if not parts:
            continue
        if "<>" in parts[0] or parts[0].startswith("0"):
            for tok in parts[1:]:
                if tok.isdigit():
                    return int(tok)
    return None


def pcap_stats(pcap_path: str) -> dict[str, Any]:
    exe = tshark_available()
    if not exe:
        return {"available": False, "reason": "tshark not found on PATH"}
    ports = [21, 22, 23, 25, 80, 104, 110, 143, 443, 445, 587, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    total_frames = _tshark_frames_count(pcap_path)
    syn_to_ports = _tshark_syn_to_ports_count(pcap_path, ports)
    return {
        "available": True,
        "tshark_path": exe,
        "total_packets": total_frames,
        "syn_packets_to_monitored_ports": syn_to_ports,
    }


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("dbs", nargs="*", help="Optional DB paths; defaults to honeypot_*_v6.db in cwd")
    ap.add_argument("--pcap-dir", default=DEFAULT_PCAP_DIR, help="PCAP directory (default: ./pcap)")
    ap.add_argument("--threshold-min", type=int, default=30, help="Max minutes difference for DB↔PCAP match (default: 30)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    dbs = get_db_paths(args.dbs if args.dbs else None)
    pcaps = discover_pcaps(args.pcap_dir)
    report: dict[str, Any] = {
        "generated_at": dt.datetime.now().isoformat(),
        "pcap_dir": str(Path(args.pcap_dir).resolve()),
        "tshark_available": bool(tshark_available()),
        "runs": [],
    }

    for db_path in dbs:
        flavor = parse_db_flavor(db_path)
        try:
            conn = sqlite3.connect(db_path)
            windows = list_run_windows(conn)
            # If we have STARTUP markers, emit one JSON entry per run window
            if windows and flavor:
                for idx, w in enumerate(windows, start=1):
                    try:
                        anchor = dt.datetime.fromisoformat(w["startup_time"])
                    except Exception:
                        anchor = None
                    run: dict[str, Any] = {
                        "db_path": str(Path(db_path).resolve()),
                        "flavor": flavor,
                        "run_index": idx,
                        "startup_id": w["startup_id"],
                        "startup_time": w["startup_time"],
                        "shutdown_time": w["shutdown_time"],
                        "end_id": w["end_id"],
                        "db_anchor_source": "STARTUP",
                    }
                    if anchor:
                        run["timing"] = time_to_first_events(
                            conn, anchor, w["startup_id"], end_id=w["end_id"]
                        )
                    else:
                        run["timing"] = None
                    run["db_metrics"] = db_metrics(conn, start_id=w["startup_id"], end_id=w["end_id"])

                    run["pcap_match"] = match_closest_pcap(pcaps, flavor, anchor, args.threshold_min) if anchor else None
                    match = run.get("pcap_match") or None
                    if match and match.get("path"):
                        run["pcap_stats"] = pcap_stats(match["path"])
                    else:
                        run["pcap_stats"] = {"available": False, "reason": "no matched pcap"}
                    report["runs"].append(run)
            else:
                # Fallback: treat entire DB as one run (older DBs without STARTUP markers)
                anchor, anchor_id, anchor_source = get_db_anchor(conn)
                run: dict[str, Any] = {
                    "db_path": str(Path(db_path).resolve()),
                    "flavor": flavor,
                    "db_anchor_time": _iso(anchor),
                    "db_anchor_source": anchor_source,
                    "db_anchor_id": anchor_id,
                    "db_metrics": db_metrics(conn),
                    "timing": time_to_first_events(conn, anchor, anchor_id) if anchor else None,
                    "pcap_match": match_closest_pcap(pcaps, flavor, anchor, args.threshold_min) if (flavor and anchor) else None,
                }
                match = run.get("pcap_match") or None
                if match and match.get("path"):
                    run["pcap_stats"] = pcap_stats(match["path"])
                else:
                    run["pcap_stats"] = {"available": False, "reason": "no matched pcap"}
                report["runs"].append(run)
            conn.close()
        except Exception as e:
            report["runs"].append(
                {"db_path": str(Path(db_path).resolve()), "flavor": flavor, "error": str(e)}
            )

    indent = 2 if args.pretty else None
    print(json.dumps(report, indent=indent, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
