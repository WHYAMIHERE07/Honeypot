import socket
import datetime
import threading
import sqlite3
import queue
import subprocess
import os
import signal

FLAVOR = "CONTROL"
BIND_IP = "0.0.0.0"
DB_NAME = f"honeypot_{FLAVOR.lower()}.db"
PCAP_FILE = f"capture_{FLAVOR.lower()}.pcap"

PORT_CONFIG = {
    21:   {"label": "FTP",      "banner": b"220 FTP server ready\r\n"},
    22:   {"label": "SSH",      "banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"},
    23:   {"label": "Telnet",   "banner": b"\r\nWelcome to Telnet\r\n"},
    25:   {"label": "SMTP",     "banner": b"220 mail.corporate-server.com ESMTP Postfix\r\n"},
    80:   {"label": "HTTP",     "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"},
    104:  {"label": "DICOM",    "banner": b"\x02\x00\x00\x00\x00\x02\x00\x00"},
    110:  {"label": "POP3",     "banner": b"+OK POP3 server ready\r\n"},
    143:  {"label": "IMAP",     "banner": b"* OK IMAP server ready\r\n"},
    443:  {"label": "HTTPS",    "banner": b""},
    445:  {"label": "SMB",      "banner": b"\x00\x00\x00\x2d\xff\x53\x4d\x42\x72\x00\x00\x00\x00"},
    587:  {"label": "SMTP-Sub", "banner": b"220 ESMTP Postfix\r\n"},
    993:  {"label": "IMAPS",    "banner": b"* OK IMAP server ready\r\n"},
    1433: {"label": "MSSQL",   "banner": b"\x04\x01\x00\x2b\x00\x00\x01\x00"},
    3306: {"label": "MySQL",   "banner": b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x32\x00"},
    3389: {"label": "RDP",     "banner": b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"},
    5432: {"label": "Postgres","banner": b"\x00\x00\x00\x08\x04\xd2\x16\x2f"},
    5900: {"label": "VNC",     "banner": b"RFB 003.008\n"},
    6379: {"label": "Redis",   "banner": b"+REDIS0010\r\n"},
    8080: {"label": "HTTP-Alt", "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
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

def db_worker():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.execute('''CREATE TABLE IF NOT EXISTS attacks 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    flavor TEXT, timestamp TEXT, port INTEGER, 
                    ip TEXT, event_type TEXT, payload TEXT)''')
    conn.commit()
    
    while True:
        item = log_queue.get()
        if item is None:
            break
        conn.execute("INSERT INTO attacks (flavor, timestamp, port, ip, event_type, payload) VALUES (?, ?, ?, ?, ?, ?)", item)
        conn.commit()
    conn.close()

def log_event(port, ip, event_type, payload=""):
    timestamp = datetime.datetime.now().isoformat()
    log_queue.put((FLAVOR, timestamp, port, ip, event_type, str(payload)))

def get_persona_response(port, data):
    flavor_banners = FLAVOR_BANNERS.get(FLAVOR, {})
    if port in flavor_banners:
        out = flavor_banners[port]
        if out is not None:
            return out
    cfg = PORT_CONFIG.get(port, {})
    return cfg.get("banner", b"")

def handle_connection(client, addr, port):
    client.settimeout(10)
    ip = addr[0]
    log_event(port, ip, "CONNECTION_ESTABLISHED")
    
    try:
        banner = get_persona_response(port, None)
        if banner:
            client.send(banner)
        
        data = client.recv(2048)
        if data:
            log_event(port, ip, "PAYLOAD_RECEIVED", data.hex())
            try:
                print(f"[!] Hit from {ip} on port {port}: {data.decode()[:50]}...")
            except Exception:
                pass
    except socket.timeout:
        log_event(port, ip, "TIMEOUT", "No data sent")
    except Exception as e:
        log_event(port, ip, "ERROR", str(e))
    finally:
        client.close()

def start_packet_capture():
    try:
        print(f"[*] Starting Packet Capture: {PCAP_FILE}")
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
    sock.bind((BIND_IP, port))
    sock.listen(100)
    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_connection, args=(client, addr, port), daemon=True).start()

if __name__ == "__main__":
    print(f"--- [ACTIVE] Flavor: {FLAVOR} | Ports: {len(PORTS)} | DB: {DB_NAME} ---")
    threading.Thread(target=db_worker, daemon=True).start()
    tcpdump_proc = start_packet_capture()
    for p in PORTS:
        threading.Thread(target=start_listener, args=(p,), daemon=True).start()
        print(f"[*] {p} ({PORT_CONFIG[p]['label']})")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        if tcpdump_proc is not None:
            try:
                os.kill(tcpdump_proc.pid, signal.SIGTERM)
            except (ProcessLookupError, AttributeError):
                pass
        log_queue.put(None)