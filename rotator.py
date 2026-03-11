"""
Rotator: cycles honeypot flavor every 5 minutes and runs a fixed-duration experiment.
Uses graceful shutdown so the honeypot can flush the DB queue before exit (avoids losing hits).
"""
import subprocess
import time
import sys
import datetime
import os
import signal

FLAVORS = ["CONTROL", "WORDPRESS", "HEALTHCARE"]
# Point to your honeypot script. Must accept flavor as first arg for flavor switching.
SCRIPT_PATH = os.environ.get("HONEYPOT_SCRIPT", "/home/ubuntu/honeypot/genericscript.py")

# Network interface for tcpdump. Auto-detect if not set (AWS/Ubuntu often use ens5, enp0s3, etc.)
def _default_interface():
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], stderr=subprocess.DEVNULL, text=True, timeout=2)
        for line in out.splitlines():
            # Skip loopback (lo), find first numbered interface like "2: ens5"
            parts = line.strip().split(": ", 2)
            if len(parts) >= 2 and parts[1] != "lo":
                return parts[1]
    except Exception:
        pass
    return "any"
TCPDUMP_INTERFACE = os.environ.get("TCPDUMP_IF") or _default_interface()

# Give honeypot this long to flush DB and exit after SIGTERM before we SIGKILL
GRACEFUL_SHUTDOWN_SEC = 10


def get_current_flavor():
    now = time.localtime()
    index = now.tm_min // 5
    return FLAVORS[index % len(FLAVORS)]


def run_experiment():
    run_seconds = int(os.environ.get("RUN_SECONDS", "300"))  # 5-minute default
    print(f"[{time.strftime('%H:%M:%S')}] Clearing ports and old captures...")
    os.system("sudo fuser -k 25/tcp 80/tcp 443/tcp 587/tcp 3389/tcp >/dev/null 2>&1")
    os.system("sudo killall tcpdump >/dev/null 2>&1")

    flavor = get_current_flavor()
    current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    pcap_dir = os.environ.get("PCAP_DIR", "/home/ubuntu/honeypot/pcap")
    if not os.path.exists(pcap_dir):
        os.makedirs(pcap_dir)
    pcap_filename = f"{pcap_dir}/{flavor}_{current_time}.pcap"

    print(f"[{time.strftime('%H:%M:%S')}] Starting experiment. Flavor: {flavor}")
    print(f"[{time.strftime('%H:%M:%S')}] PCAP file: {pcap_filename}")

    # Launch honeypot (flavor as first arg if genericscript expects it)
    env = os.environ.copy()
    env["FLAVOR"] = flavor
    hp_proc = subprocess.Popen(
        ["sudo", "-E", "python3", SCRIPT_PATH, flavor],
        preexec_fn=os.setsid,
        env=env,
    )

    # Use "any" so traffic is captured regardless of interface (avoids 0 packets on wrong iface)
    dump_cmd = [
        "sudo", "tcpdump", "-i", "any", "-w", pcap_filename,
        "port 25 or port 80 or port 443 or port 587 or port 3389", "-U",
    ]
    sniff_proc = subprocess.Popen(dump_cmd, preexec_fn=os.setsid)

    try:
        time.sleep(run_seconds)
    except KeyboardInterrupt:
        print("\nManual stop detected.")

    print(f"[{time.strftime('%H:%M:%S')}] Stopping experiment: {flavor} (graceful shutdown)")

    # Graceful shutdown: SIGTERM first so honeypot can flush DB, then SIGKILL if needed
    for proc, name in [(hp_proc, "honeypot"), (sniff_proc, "tcpdump")]:
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            proc.wait(timeout=GRACEFUL_SHUTDOWN_SEC)
        except subprocess.TimeoutExpired:
            print(f"[{time.strftime('%H:%M:%S')}] {name} did not exit in {GRACEFUL_SHUTDOWN_SEC}s, sending SIGKILL")
            try:
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass
        except ProcessLookupError:
            pass
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error stopping {name}: {e}")

    print(f"[{time.strftime('%H:%M:%S')}] Experiment ended.")


if __name__ == "__main__":
    # Test period suggestion: RUN_SECONDS=300 (5 min) for each cycle.
    # For a 15 minute test that hits all 3 flavors once: set CYCLES=3.
    cycles = int(os.environ.get("CYCLES", "0"))  # 0 => run forever
    n = 0
    while True:
        run_experiment()
        n += 1
        if cycles and n >= cycles:
            break
        time.sleep(1)
