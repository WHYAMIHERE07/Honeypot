"""
Honeypot V6 – Fixes DB persistence, logs all attempts, interactive responses, decoded payloads.
- All connection attempts logged (including connect-and-close with no data).
- Protocol-specific responses to elicit more behaviour.
- Base64/hex payloads decoded and stored for analysis.
"""

import socket
import datetime
import threading
import sqlite3
import queue
import subprocess
import os
import signal
import re
import base64
import time
import sys
import uuid

FLAVOR = "CONTROL"
VALID_FLAVORS = ("CONTROL", "WORDPRESS", "HEALTHCARE")
# Allow rotator to set flavor: python3 honeypotV6.py WORDPRESS  or  FLAVOR=HEALTHCARE python3 honeypotV6.py
if len(sys.argv) >= 2 and sys.argv[1].upper() in VALID_FLAVORS:
    FLAVOR = sys.argv[1].upper()
elif os.environ.get("FLAVOR") and os.environ.get("FLAVOR").upper() in VALID_FLAVORS:
    FLAVOR = os.environ.get("FLAVOR").upper()
BIND_IP = "0.0.0.0"
DB_NAME = f"honeypot_{FLAVOR.lower()}_v6.db"
# PCAP path set at startup in __main__ to pcap/{FLAVOR}_{timestamp}.pcap
PCAP_DIR = os.environ.get("PCAP_DIR", "pcap")
PCAP_FILE = None  # set when main runs

PORT_CONFIG = {
    21:   {"label": "FTP",      "banner": b"220 FTP server ready\r\n"},
    22:   {"label": "SSH",      "banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"},
    23:   {"label": "Telnet",   "banner": b"\r\nWelcome to Telnet\r\n"},
    25:   {"label": "SMTP",     "banner": b"220 mail.corporate-server.com ESMTP Postfix\r\n"},
    80:   {"label": "HTTP",     "banner": None},  # Response built per request
    104:  {"label": "DICOM",    "banner": b"\x02\x00\x00\x00\x00\x02\x00\x00"},
    110:  {"label": "POP3",     "banner": b"+OK POP3 server ready\r\n"},
    143:  {"label": "IMAP",     "banner": b"* OK IMAP server ready\r\n"},
    443:  {"label": "HTTPS",    "banner": b""},
    445:  {"label": "SMB",      "banner": b"\x00\x00\x00\x2d\xff\x53\x4d\x42\x72\x00\x00\x00\x00"},
    587:  {"label": "SMTP-Sub", "banner": b"220 ESMTP Postfix\r\n"},
    993:  {"label": "IMAPS",    "banner": b"* OK IMAP server ready\r\n"},
    1433: {"label": "MSSQL",    "banner": b"\x04\x01\x00\x2b\x00\x00\x01\x00"},
    3306: {"label": "MySQL",    "banner": b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x32\x00"},
    3389: {"label": "RDP",      "banner": b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"},
    5432: {"label": "Postgres", "banner": b"\x00\x00\x00\x08\x04\xd2\x16\x2f"},
    5900: {"label": "VNC",      "banner": b"RFB 003.008\n"},
    6379: {"label": "Redis",    "banner": b"+REDIS0010\r\n"},
    8080: {"label": "HTTP-Alt", "banner": None},
    8443: {"label": "HTTPS-Alt", "banner": b""},
}
PORTS = list(PORT_CONFIG.keys())

FLAVOR_BANNERS = {
    "CONTROL": {},
    "WORDPRESS": {
        80:   b"HTTP/1.1 200 OK\r\nServer: WordPress/6.4.2\r\nX-Pingback: /xmlrpc.php\r\n\r\n",
        443:  b"",
        8080: b"HTTP/1.1 200 OK\r\nServer: WordPress/6.4.2\r\nX-Pingback: /xmlrpc.php\r\n\r\n",
    },
    "HEALTHCARE": {
        80:   b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-NHS-Portal: Internal-v2\r\n\r\n",
        443:  b"",
        104:  b"\x02\x00\x00\x00\x00\x02\x00\x00",
        3389: b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00",
        1433: b"\x04\x01\x00\x2b\x00\x00\x01\x00",
    },
}

log_queue = queue.Queue()
db_worker_thread = None
shutdown_requested = False
sense_proc = None
sense_thread = None


def _request_shutdown(*_args):
    """Called on SIGTERM/SIGINT so rotator (or Ctrl+C) gets graceful DB flush."""
    global shutdown_requested
    shutdown_requested = True


def _tcpdump_syn_filter() -> str:
    # SYN only (no ACK) to monitored ports
    ports = " or ".join([f"tcp dst port {p}" for p in PORTS])
    return f"tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and ({ports})"


_TCPDUMP_LINE_RE = re.compile(
    r"^(?P<ts>\d+(?:\.\d+)?)\s+IP6?\s+"
    r"(?P<src>[^\s>]+)\s+>\s+(?P<dst>[^\s:]+)\.(?P<dport>\d+):\s+"
)


def _split_host_port(addr: str) -> tuple[str, int]:
    # Handles IPv4 like 1.2.3.4.12345 and IPv6 like 2001:db8::1.12345
    if "." not in addr:
        return addr, 0
    host, port_s = addr.rsplit(".", 1)
    try:
        return host, int(port_s)
    except Exception:
        return host, 0


def _sense_syn_loop(proc: subprocess.Popen):
    while not shutdown_requested:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            break
        m = _TCPDUMP_LINE_RE.match(line.strip())
        if not m:
            continue
        src = m.group("src")
        dport = int(m.group("dport"))
        src_ip, src_port = _split_host_port(src)
        # event_type SYN_SEEN is the key for half-open/scan attempts
        log_event(dport, src_port, src_ip, "SYN_SEEN", payload=line.strip())


def start_syn_sense():
    """
    Packet-level logging to capture scan attempts that never reach accept().
    Uses tcpdump line mode and parses SYN packets to our monitored TCP ports.
    """
    global sense_proc, sense_thread
    try:
        cmd = [
            "tcpdump",
            "-i",
            "any",
            "-l",
            "-n",
            "-tt",
            _tcpdump_syn_filter(),
        ]
        if os.name != "nt":
            cmd = ["sudo"] + cmd
        sense_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        sense_thread = threading.Thread(target=_sense_syn_loop, args=(sense_proc,), daemon=True)
        sense_thread.start()
        print("[*] SYN sensing enabled (logs SYN_SEEN even without handshake)")
    except FileNotFoundError:
        print("[*] tcpdump not found; SYN sensing skipped")
        sense_proc = None
        sense_thread = None
    except Exception as e:
        print(f"[*] SYN sensing failed: {e}")
        sense_proc = None
        sense_thread = None


def decode_payload(raw: str, as_bytes: bytes = None) -> tuple:
    """
    Try to decode base64 or hex from payload. Returns (decoded_str, encoding_used).
    encoding_used is one of: 'base64', 'hex', 'utf8', None.
    """
    if as_bytes is not None:
        # Try UTF-8 first for display
        try:
            s = as_bytes.decode("utf-8", errors="strict")
            if s.isprintable() or "\n" in s or "\r" in s:
                return s, "utf8"
        except Exception:
            pass
        # Try hex (binary payload)
        if len(as_bytes) <= 2048:
            try:
                h = as_bytes.hex()
                return h, "hex_raw"
            except Exception:
                pass
        return as_bytes.decode("utf-8", errors="replace"), None

    s = raw.strip()
    if not s:
        return "", None

    # Looks like hex (even length, only hex chars)
    hex_candidate = re.sub(r"\s+", "", s)
    if len(hex_candidate) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", hex_candidate):
        try:
            decoded = bytes.fromhex(hex_candidate).decode("utf-8", errors="replace")
            return decoded, "hex"
        except Exception:
            try:
                return bytes.fromhex(hex_candidate).hex(), "hex_bin"
            except Exception:
                pass

    # Try base64
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8", errors="replace"), "base64"
    except Exception:
        pass
    try:
        decoded = base64.urlsafe_b64decode(s + "==")
        return decoded.decode("utf-8", errors="replace"), "base64"
    except Exception:
        pass

    return "", None


def db_worker():
    """Process log queue and write to SQLite. Resilient to single-row failures; runs until sentinel."""
    global db_worker_thread
    conn = sqlite3.connect(DB_NAME, check_same_thread=False, timeout=15.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flavor TEXT,
            timestamp TEXT,
            port INTEGER,
            src_port INTEGER,
            ip TEXT,
            event_type TEXT,
            payload TEXT,
            payload_decoded TEXT,
            payload_encoding TEXT,
            response_sent TEXT,
            connection_id TEXT,
            exchange_index INTEGER
        )
    """)
    # Add columns for existing DBs (no-op if already present)
    for name, ctype in (("connection_id", "TEXT"), ("exchange_index", "INTEGER")):
        try:
            conn.execute(f"ALTER TABLE attacks ADD COLUMN {name} {ctype}")
            conn.commit()
        except sqlite3.OperationalError:
            pass
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ts_ip_port ON attacks(timestamp, ip, port)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_event ON attacks(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_connection ON attacks(connection_id)")
    conn.commit()

    while True:
        item = log_queue.get()
        if item is None:
            break
        try:
            conn.execute(
                """INSERT INTO attacks (flavor, timestamp, port, src_port, ip, event_type, payload,
                   payload_decoded, payload_encoding, response_sent, connection_id, exchange_index)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                item,
            )
            conn.commit()
        except Exception as e:
            print(f"[DB ERROR] {e}", flush=True)
            try:
                conn.rollback()
            except Exception:
                pass
    # Consolidate WAL into main DB on normal shutdown
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
    except Exception as e:
        print(f"[DB CHECKPOINT ERROR] {e}", flush=True)
    finally:
        conn.close()


def log_event(port, src_port, ip, event_type, payload="", payload_decoded="", payload_encoding="", response_sent="",
              connection_id=None, exchange_index=None):
    timestamp = datetime.datetime.now().isoformat()
    log_queue.put((
        FLAVOR, timestamp, port, src_port, ip, event_type,
        str(payload)[:8192],  # cap size
        str(payload_decoded)[:8192],
        str(payload_encoding),
        str(response_sent)[:1024],
        connection_id,
        exchange_index if exchange_index is not None else None,
    ))


def get_persona_response(port):
    flavor_banners = FLAVOR_BANNERS.get(FLAVOR, {})
    if port in flavor_banners and flavor_banners[port]:
        return flavor_banners[port]
    cfg = PORT_CONFIG.get(port, {})
    return cfg.get("banner") or b""


def build_http_response(method, path, raw_request: bytes) -> bytes:
    """Build scenario-appropriate HTTP response to encourage more interaction."""
    path = path.split("?")[0].strip("/") or "/"
    if method.upper() == "GET":
        if path in ("", "/"):
            body = b"<html><head><title>Index</title></head><body><h1>Welcome</h1><p>Server is running.</p></body></html>"
            return (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
        if "xmlrpc" in path or "wp-" in path or "admin" in path:
            body = b"<?xml version='1.0'?><methodResponse><fault><value>Permission denied</value></fault></methodResponse>"
            return (
                b"HTTP/1.1 403 Forbidden\r\n"
                b"Server: Apache/2.4.41\r\n"
                b"Content-Type: text/xml\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
            )
        if "shell" in path or "cmd" in path or ".php" in path or "eval" in path:
            body = b""
            return b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"
        # Generic 404 for other paths
        return b"HTTP/1.1 404 Not Found\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"
    if method.upper() == "POST":
        body = b"<html><body><h1>501 Not Implemented</h1></body></html>"
        return (
            b"HTTP/1.1 501 Not Implemented\r\n"
            b"Server: Apache/2.4.41\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
    return b"HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n"


def build_ftp_response(line: bytes) -> bytes:
    """Minimal FTP replies to keep session alive and log commands."""
    upper = line.upper().strip()
    if upper.startswith(b"USER "):
        return b"331 Password required\r\n"
    if upper.startswith(b"PASS "):
        return b"230 Login successful\r\n"
    if upper.startswith(b"SYST"):
        return b"215 UNIX Type: L8\r\n"
    if upper.startswith(b"PWD") or upper.startswith(b"XPWD"):
        return b'257 "/" is current directory\r\n'
    if upper.startswith(b"TYPE "):
        return b"200 Type set\r\n"
    if upper.startswith(b"PASV") or upper.startswith(b"PORT"):
        return b"200 OK\r\n"
    if upper.startswith(b"LIST") or upper.startswith(b"NLST"):
        return b"150 Here comes the directory listing\r\n"  # Data connection would follow; client may send more on control
    if upper.startswith(b"QUIT"):
        return b"221 Goodbye\r\n"
    return b"502 Command not implemented\r\n"


def build_smtp_response(line: bytes) -> bytes:
    upper = line.upper().strip()
    if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
        return b"250-mail.corporate-server.com Hello\r\n250-SIZE 52428800\r\n250 8BITMIME\r\n"
    if upper.startswith(b"MAIL FROM"):
        return b"250 2.1.0 OK\r\n"
    if upper.startswith(b"RCPT TO"):
        return b"250 2.1.5 OK\r\n"
    if upper.startswith(b"DATA"):
        return b"354 End data with <CR><LF>.<CR><LF>\r\n"
    if upper.startswith(b"QUIT"):
        return b"221 Bye\r\n"
    if upper.startswith(b"RSET") or upper.startswith(b"NOOP"):
        return b"250 OK\r\n"
    return b"250 OK\r\n"


def handle_connection(client, addr, port):
    client.settimeout(15)
    ip, src_port = addr[0], addr[1]
    connection_id = uuid.uuid4().hex[:12]

    # Log every connection attempt immediately (even if handshake never completes)
    log_event(port, src_port, ip, "CONNECTION_ESTABLISHED", "", "", "", "",
              connection_id=connection_id, exchange_index=0)
    received_any = False

    try:
        banner = get_persona_response(port)
        # HTTP ports: no banner; wait for request
        if port not in (80, 8080, 443, 8443) and banner is not None and banner != b"":
            client.send(banner)
            log_event(port, src_port, ip, "BANNER_SENT", "", "", "", "banner",
                      connection_id=connection_id, exchange_index=0)

        for exchange in range(10):  # Allow more exchanges for interactive protocols
            data = client.recv(8192)
            if not data:
                if not received_any:
                    log_event(port, src_port, ip, "CONNECTION_CLOSED_NO_DATA", "", "", "", "",
                              connection_id=connection_id, exchange_index=0)
                break
            received_any = True

            payload_preview = ""
            payload_decoded = ""
            payload_encoding = ""
            response_sent = ""

            try:
                decoded_data = data.decode("utf-8", errors="ignore")
            except Exception:
                decoded_data = ""

            # Protocol-specific response and logging
            if port in (80, 8080, 443, 8443):
                lines = decoded_data.split("\n")
                first = lines[0].strip() if lines else ""
                if "GET " in first or "POST " in first or "HEAD " in first:
                    parts = first.split()
                    method = parts[0] if len(parts) > 0 else ""
                    path = parts[1] if len(parts) > 1 else ""
                    payload_preview = first
                    resp = build_http_response(method, path, data)
                    client.send(resp)
                    response_sent = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
                    dec, enc = decode_payload("", data)
                    payload_decoded = dec
                    payload_encoding = enc or "raw"
                    log_event(port, src_port, ip, "HTTP_REQUEST", payload_preview, payload_decoded, payload_encoding, response_sent,
                              connection_id=connection_id, exchange_index=exchange + 1)
                else:
                    payload_preview = data.hex() if len(data) < 256 else data[:128].hex() + "..."
                    dec, enc = decode_payload("", data)
                    payload_decoded = dec
                    payload_encoding = enc or "raw"
                    log_event(port, src_port, ip, f"PAYLOAD_STAGE_{exchange + 1}", payload_preview, payload_decoded, payload_encoding, "",
                              connection_id=connection_id, exchange_index=exchange + 1)
                    client.send(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            elif port == 21:
                payload_preview = decoded_data.strip() or data.hex()
                reply = build_ftp_response(data)
                client.send(reply)
                response_sent = reply.decode("utf-8", errors="replace").strip()
                dec, enc = decode_payload(payload_preview)
                if not dec and payload_preview:
                    dec, enc = decode_payload("", data)
                payload_decoded = dec
                payload_encoding = enc or ""
                log_event(port, src_port, ip, "FTP_COMMAND", payload_preview, payload_decoded, payload_encoding, response_sent,
                          connection_id=connection_id, exchange_index=exchange + 1)
            elif port in (25, 587):
                payload_preview = decoded_data.strip() or data.hex()
                reply = build_smtp_response(data)
                client.send(reply)
                response_sent = reply.split(b"\r\n")[0].decode("utf-8", errors="replace")
                dec, enc = decode_payload(payload_preview)
                if not dec and payload_preview:
                    dec, enc = decode_payload("", data)
                payload_decoded = dec
                payload_encoding = enc or ""
                log_event(port, src_port, ip, "SMTP_COMMAND", payload_preview, payload_decoded, payload_encoding, response_sent,
                          connection_id=connection_id, exchange_index=exchange + 1)
            else:
                payload_preview = decoded_data.strip() if decoded_data.strip() else data.hex()
                dec, enc = decode_payload(payload_preview)
                if not dec and payload_preview and not decoded_data.strip():
                    dec, enc = decode_payload("", data)
                payload_decoded = dec
                payload_encoding = enc or ""
                log_event(port, src_port, ip, f"PAYLOAD_STAGE_{exchange + 1}", payload_preview, payload_decoded, payload_encoding, "",
                          connection_id=connection_id, exchange_index=exchange + 1)
                # Generic keep-alive for other protocols
                if PORT_CONFIG.get(port, {}).get("label") in ("Telnet", "POP3", "IMAP"):
                    client.send(b"\r\n")
                else:
                    client.send(b"\r\n")

            print(f"[!] Hit {ip}:{src_port} port {port} | {payload_preview[:80]}...")
    except socket.timeout:
        log_event(port, src_port, ip, "TIMEOUT", "No more data", "", "", "",
                  connection_id=connection_id, exchange_index=None)
    except ConnectionResetError:
        log_event(port, src_port, ip, "CONNECTION_RESET", "", "", "", "",
                  connection_id=connection_id, exchange_index=None)
    except Exception as e:
        log_event(port, src_port, ip, "ERROR", str(e), "", "", "",
                  connection_id=connection_id, exchange_index=None)
    finally:
        try:
            client.close()
        except Exception:
            pass


def start_packet_capture():
    if not PCAP_FILE:
        return None
    try:
        print(f"[*] Starting packet capture: {PCAP_FILE}")
        port_filter = " or ".join([f"port {p}" for p in PORTS])
        cmd = ["tcpdump", "-i", "any", "-w", PCAP_FILE, port_filter]
        if os.name != "nt":
            cmd = ["sudo"] + cmd
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[*] tcpdump not found; packet capture skipped")
        return None


def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((BIND_IP, port))
        sock.listen(100)
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr, port), daemon=True).start()
    except Exception as e:
        print(f"[!] Could not start listener on port {port}: {e}")


def _do_shutdown(tcpdump_proc):
    print("\n[!] Shutting down – flushing DB queue...")
    # Stop sensing first so it doesn't keep enqueueing while we're flushing
    global sense_proc
    if sense_proc is not None:
        try:
            os.kill(sense_proc.pid, signal.SIGTERM)
        except Exception:
            try:
                sense_proc.terminate()
            except Exception:
                pass
    log_queue.put(None)
    db_worker_thread.join(timeout=10)
    # Force a WAL checkpoint so the main DB file is consolidated on Ctrl+C/SIGTERM
    try:
        conn = sqlite3.connect(DB_NAME, timeout=10.0)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB CHECKPOINT ERROR] {e}", flush=True)
    if tcpdump_proc is not None:
        try:
            os.kill(tcpdump_proc.pid, signal.SIGTERM)
        except (ProcessLookupError, AttributeError):
            pass
    print("[*] Done.")


if __name__ == "__main__":
    # Graceful shutdown on SIGTERM (e.g. from rotator) and Ctrl+C
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _request_shutdown)

    # PCAP in pcap folder: {flavor}_{timestamp}.pcap for easier searching (no global needed at module level)
    os.makedirs(PCAP_DIR, exist_ok=True)
    PCAP_FILE = os.path.join(PCAP_DIR, f"{FLAVOR}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")

    print(f"--- [ACTIVE] Honeypot V6 | Flavor: {FLAVOR} | Ports: {len(PORTS)} | DB: {DB_NAME} ---")
    print(f"[*] PCAP: {PCAP_FILE}")

    db_worker_thread = threading.Thread(target=db_worker, daemon=False)
    db_worker_thread.start()

    # Start packet-level sensing for half-open attempts
    start_syn_sense()

    tcpdump_proc = start_packet_capture()

    for p in PORTS:
        threading.Thread(target=start_listener, args=(p,), daemon=True).start()
        print(f"[*] Monitoring: {p} ({PORT_CONFIG[p]['label']})")

    try:
        while not shutdown_requested:
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown_requested = True
    finally:
        _do_shutdown(tcpdump_proc)


# --- Analysis tips (for later) ---
# - Query by event_type: CONNECTION_ESTABLISHED (all hits), CONNECTION_CLOSED_NO_DATA (scan-only),
#   HTTP_REQUEST, FTP_COMMAND, PAYLOAD_STAGE_* (raw probes).
# - payload_decoded + payload_encoding show what was attempted when payload was base64/hex.
# - response_sent shows what the honeypot replied (useful to correlate with attacker next steps).
# - Indexes on (timestamp, ip, port) and event_type speed up time-range and event filters.
# - To list unique IPs per port: SELECT DISTINCT ip, port, COUNT(*) FROM attacks GROUP BY ip, port;
# - To see only decoded payloads: SELECT * FROM attacks WHERE payload_encoding IN ('base64','hex');
