"""
Honeypot V6 – analysis helpers. Use the SQLite DB; no need to open PCAPs for response flow.
- attacks table: payload (what they sent), response_sent (what we sent), connection_id, exchange_index.
- Use connection_id to see full request/response conversations and what happened after our responses.
"""
import sqlite3
import sys
import os

# Default: all flavor DBs in current dir; or pass path(s) as args
DB_GLOB = "honeypot_*_v6.db"


def get_dbs(paths=None):
    if paths:
        return [p for p in paths if os.path.isfile(p)]
    import glob
    return glob.glob(DB_GLOB)


def schema(conn):
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [r[0] for r in cur.fetchall()]
    for t in tables:
        cur = conn.execute(f"PRAGMA table_info({t})")
        print(f"\nTable: {t}")
        for r in cur.fetchall():
            print(f"  {r[1]} {r[2]}")
    return tables


def summary(conn):
    cur = conn.execute(
        "SELECT COUNT(*), COUNT(DISTINCT ip), COUNT(DISTINCT connection_id) FROM attacks"
    )
    total, unique_ips, unique_conns = cur.fetchone()
    print(f"Total events: {total}  |  Unique IPs: {unique_ips}  |  Connections (with id): {unique_conns}")
    cur = conn.execute(
        "SELECT event_type, COUNT(*) FROM attacks GROUP BY event_type ORDER BY 2 DESC"
    )
    print("\nBy event_type:")
    for row in cur.fetchall():
        print(f"  {row[0]}: {row[1]}")
    return total


def conversation(conn, connection_id):
    """Print full request/response flow for one connection (what they sent → what we sent)."""
    cur = conn.execute(
        """SELECT id, timestamp, event_type, port, exchange_index,
                  payload, response_sent
           FROM attacks WHERE connection_id = ? ORDER BY id""",
        (connection_id,),
    )
    rows = cur.fetchall()
    if not rows:
        print(f"No rows for connection_id={connection_id}")
        return
    print(f"--- Connection {connection_id} ({len(rows)} events) ---")
    for r in rows:
        id_, ts, ev, port, ex, payload, resp = r
        payload_preview = (payload or "")[:200] + ("..." if len(payload or "") > 200 else "")
        resp_preview = (resp or "")[:120] + ("..." if len(resp or "") > 120 else "")
        print(f"  [{id_}] {ts}  port={port}  ex={ex}  {ev}")
        print(f"      they sent: {payload_preview}")
        print(f"      we sent:   {resp_preview}")
    return rows


def conversations_with_followup(conn, min_exchanges=2):
    """List connection_ids that had multiple exchanges (so we sent something and they sent more)."""
    cur = conn.execute(
        """SELECT connection_id, COUNT(*) as n
           FROM attacks WHERE connection_id IS NOT NULL
           GROUP BY connection_id HAVING n >= ?
           ORDER BY n DESC""",
        (min_exchanges,),
    )
    rows = cur.fetchall()
    print(f"Connections with at least {min_exchanges} events (our response → their next move):")
    for cid, n in rows[:50]:
        print(f"  {cid}  ({n} events)")
    return [r[0] for r in rows]


def top_ips(conn, limit=20):
    cur = conn.execute(
        "SELECT ip, COUNT(*) as n FROM attacks GROUP BY ip ORDER BY n DESC LIMIT ?",
        (limit,),
    )
    rows = cur.fetchall()
    print("Top IPs by event count:")
    for ip, n in rows:
        print(f"  {ip}: {n}")
    return rows


def main():
    paths = sys.argv[1:] if len(sys.argv) > 1 else None
    dbs = get_dbs(paths)
    if not dbs:
        print("No DBs found. Usage: python analysis.py [honeypot_control_v6.db ...]")
        return
    for dbpath in dbs:
        print(f"\n========== {dbpath} ==========")
        conn = sqlite3.connect(dbpath)
        schema(conn)
        summary(conn)
        print("\n--- Sample: connections with follow-up (multi-exchange) ---")
        conversations_with_followup(conn, min_exchanges=2)
        print("\n--- Top IPs ---")
        top_ips(conn, 10)
        # Show one full conversation if any exist
        cur = conn.execute(
            "SELECT connection_id FROM attacks WHERE connection_id IS NOT NULL LIMIT 1"
        )
        row = cur.fetchone()
        if row:
            print("\n--- One full conversation (request → response → next request...) ---")
            conversation(conn, row[0])
        conn.close()


if __name__ == "__main__":
    main()
