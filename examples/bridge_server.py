"""
Example: MT5 RPyC bridge server, generalized from a real production setup.

Runs inside Wine Python. Loads patch_wine_mt5 to bypass the IPC timeout,
attaches to a running terminal64.exe, and exposes the MetaTrader5 module
over RPyC so a native Linux Python process can drive it.

This is a simplified/generalized version of a real bridge service --
broker-specific paths and account handling have been stripped out. It's
included to show the patch actually being used, not as a drop-in
production script: add your own retry/health-check logic, credential
handling, and process supervision (e.g. systemd) around this.

Usage:
    wine python.exe bridge_server.py <port> [path\\to\\terminal64.exe]
"""

import sys
import os
import time
import rpyc
from rpyc.utils.server import ThreadedServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import patch_wine_mt5
    print("[BRIDGE] Wine MT5 IPC patch active.", flush=True)
except Exception as e:
    print(f"[BRIDGE] Warning: patch_wine_mt5 not loaded: {e}", flush=True)

import MetaTrader5 as mt5

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18812

# Point this at your own terminal install -- nothing broker-specific is
# hardcoded here. Pass it as argv[2], or edit the fallback list below.
if len(sys.argv) > 2:
    terminal_path = sys.argv[2]
else:
    possible_paths = [
        r"C:\Program Files\MetaTrader 5\terminal64.exe",
    ]
    terminal_path = next((p for p in possible_paths if os.path.exists(p)), None)

print(f"[BRIDGE-{port}] Detected terminal path: {terminal_path}", flush=True)

attached = False
for attempt in range(1, 10):
    try:
        if mt5.initialize(path=terminal_path, portable=True, timeout=5000):
            attached = True
            break
    except Exception as e:
        print(f"[BRIDGE-{port}] Init exception: {e}", flush=True)
    print(f"[BRIDGE-{port}] Waiting for MT5 window (attempt {attempt}/10)...", flush=True)
    time.sleep(2)

if not attached:
    print(f"[BRIDGE-{port}] FATAL: mt5.initialize() failed: {mt5.last_error()}", flush=True)
    sys.exit(1)

acc = mt5.account_info()
term = mt5.terminal_info()
if acc:
    # Log connection health without printing the account/login number.
    print(f"[BRIDGE-{port}] ATTACHED: Server={acc.server} | Build={term.build if term else 'N/A'}", flush=True)
else:
    print(f"[BRIDGE-{port}] ATTACHED to terminal build {term.build if term else 'N/A'}, waiting for broker sync...", flush=True)


class MT5Service(rpyc.Service):
    exposed_mt5 = mt5


print(f"[BRIDGE-{port}] Starting RPyC MT5Service on 127.0.0.1:{port}...", flush=True)
server = ThreadedServer(
    MT5Service,
    port=port,
    hostname="127.0.0.1",
    protocol_config={
        "allow_public_attrs": True,
        "allow_all_attrs": True,
        "allow_pickle": True,
        "sync_request_timeout": 120,
    }
)
server.start()
