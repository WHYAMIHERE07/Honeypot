import socket
import datetime
import threading
import sqlite3

PORTS = [25, 587, 80, 443]
BIND_IP = "0.0.0.0"
DB_NAME = "honeypot_results.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  port INTEGER, 
                  ip TEXT, 
                  payload TEXT)''')
    conn.commit()
    conn.close()

def log_to_db(port, remote_ip, data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO attacks (timestamp, port, ip, payload) VALUES (?, ?, ?, ?)", 
                  (timestamp, port, remote_ip, data))
        conn.commit()
        conn.close()
        print(f"[*] Recorded: {remote_ip} on port {port}")
    except Exception as e:
        print(f"Database error: {e}")

def handle_connection(client_socket, remote_addr, port):
    try:
        if port in [25, 587]:
            banner = b"220 corp-mail-01.internal.local ESMTP Postfix (Ubuntu)\r\n"
        elif port in [80, 443]:
            banner = b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n"
        else:
            banner = b"Unauthorized Access Prohibited\r\n"
        
        client_socket.send(banner)

        client_socket.settimeout(5.0)
        payload = client_socket.recv(1024)
        
        log_to_db(port, remote_addr[0], payload.hex())
        
        client_socket.close()
    except Exception:
        log_to_db(port, remote_addr[0], "No payload - Disconnected")

def start_honeypot(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, port))
    server.listen(10)
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_connection, args=(client, addr, port)).start()

if __name__ == "__main__":
    print(f"--- [STARTING] Corporate Honeypot on {PORTS} ---")
    init_db()
    for p in PORTS:
        t = threading.Thread(target=start_honeypot, args=(p,))
        t.daemon = True
        t.start()
    
    try:
        while True: pass
    except KeyboardInterrupt:
        print("\n--- [STOPPING] Honeypot ---")
