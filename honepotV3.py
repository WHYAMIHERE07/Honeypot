import socket
import datetime
import threading
import sqlite3
import logging

BIND_IP = "0.0.0.0"
DB_NAME = "research_honeypot.db"
PORT_CONFIG = {
    25:   {"label": "SMTP", "banner": b"220 mail01.nhs.uk ESMTP Postfix\r\n"},
    80:   {"label": "HTTP-WP", "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n\r\n"},
    443:  {"label": "HTTPS", "banner": b""},
    445:  {"label": "SMB", "banner": b"\x00\x00\x00\x2d\xff\x53\x4d\x42\x72\x00\x00\x00\x00"}, 
    104:  {"label": "Medical-DICOM", "banner": b"\x02\x00\x00\x00\x00\x02\x00\x00"},
    3389: {"label": "RDP", "banner": b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"},
    502:  {"label": "Industrial-Modbus", "banner": b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"}
}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] Port %(port)s from %(ip)s: %(message)s'
)

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS attacks 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      timestamp TEXT, port INTEGER, label TEXT, ip TEXT, 
                      payload TEXT)''')

def log_event(port, ip, label, payload):
    extra = {'port': port, 'ip': ip}
    logger = logging.LoggerAdapter(logging.getLogger(), extra)
    logger.info(f"Interaction detected on {label}")
    
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO attacks (timestamp, port, label, ip, payload) VALUES (?, ?, ?, ?, ?)",
                     (datetime.datetime.now().isoformat(), port, label, ip, str(payload)))

def handle_connection(client, addr, port):
    client.settimeout(10)
    ip = addr[0]
    config = PORT_CONFIG.get(port)
    label = config['label']
    
    try:
        log_event(port, ip, label, "[CONN_OPEN]")
        
        if config['banner']:
            client.send(config['banner'])
        
        data = client.recv(2048)
        if data:
            log_event(port, ip, label, data.hex())
            
    except Exception as e:
        pass
    finally:
        client.close()

def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((BIND_IP, port))
        sock.listen(100)
        while True:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr, port)).start()
    except Exception as e:
        print(f"Error on port {port}: {e}")

if __name__ == "__main__":
    init_db()
    print(f"--- [Honeypot Active: Monitoring {len(PORT_CONFIG)} Services] ---")
    for p in PORT_CONFIG.keys():
        threading.Thread(target=start_listener, args=(p,), daemon=True).start()
    
    while True:
        import time
        time.sleep(1)