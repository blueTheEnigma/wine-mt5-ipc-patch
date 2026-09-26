"""
Diagnostic tool: hooks CreateFileW, WriteFile, and ReadFile in the
MetaTrader5 _core.cp311-win_amd64.pyd Import Address Table and prints every
byte crossing the Named Pipe between the extension and the running
terminal.

This is the tool used to discover the 0x6d status-polling loop and its
12-byte reply layout that patch_wine_mt5.py fixes -- see that file's
docstring, and the accompanying write-up, for the full story.

Usage:
    wine python.exe dump_core_traffic.py "C:\\Program Files\\MetaTrader 5\\terminal64.exe"

If you omit the path argument, it falls back to the default install
location MetaTrader5's Python package expects. Point it at your own
terminal64.exe -- this script does not hardcode any specific broker.
"""

import ctypes
from ctypes import wintypes
import sys
import os

print("=" * 60, flush=True)
print("DUMPING REAL _core.pyd NAMED PIPE TRAFFIC VIA IAT HOOK", flush=True)
print("=" * 60, flush=True)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# First load MetaTrader5
import MetaTrader5 as mt5

# Find _core base address
GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
GetModuleHandleW.restype = wintypes.HMODULE

h_mod = GetModuleHandleW("_core.cp311-win_amd64.pyd")
if not h_mod:
    h_mod = GetModuleHandleW("_core")
print(f"[*] _core module handle: {hex(h_mod)}", flush=True)

# RVAs specific to build 6230's _core.cp311-win_amd64.pyd. If your build
# differs, these are exactly what this script re-derives via the printed
# hook installs below -- run once, note the handle, and use a PE parser
# (e.g. pefile) against your own _core*.pyd to confirm/update them.
write_iat_rva = 0x140f0
read_iat_rva = 0x140f8
create_iat_rva = 0x140b8

print(f"[*] WriteFile IAT RVA: {hex(write_iat_rva)}", flush=True)
print(f"[*] ReadFile IAT RVA: {hex(read_iat_rva)}", flush=True)
print(f"[*] CreateFileW IAT RVA: {hex(create_iat_rva)}", flush=True)

VirtualProtect = kernel32.VirtualProtect
VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
VirtualProtect.restype = wintypes.BOOL

PAGE_EXECUTE_READWRITE = 0x40

# Prototypes
WRITEFILE_PROTO = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
READFILE_PROTO = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
CREATEFILEW_PROTO = ctypes.WINFUNCTYPE(wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)

orig_WriteFile_addr = ctypes.c_uint64.from_address(h_mod + write_iat_rva).value
orig_ReadFile_addr = ctypes.c_uint64.from_address(h_mod + read_iat_rva).value
orig_CreateFileW_addr = ctypes.c_uint64.from_address(h_mod + create_iat_rva).value

real_WriteFile = WRITEFILE_PROTO(orig_WriteFile_addr)
real_ReadFile = READFILE_PROTO(orig_ReadFile_addr)
real_CreateFileW = CREATEFILEW_PROTO(orig_CreateFileW_addr)

pipe_handles = set()

def my_CreateFileW(name, access, share, sec, disp, flags, template):
    h = real_CreateFileW(name, access, share, sec, disp, flags, template)
    err = ctypes.get_last_error()
    if name and "pipe" in str(name).lower():
        print(f"\n[IAT HOOK CreateFileW] Pipe: '{name}' -> Handle: {hex(h)}, Err: {err}", flush=True)
        if h and h != -1:
            pipe_handles.add(h)
    return h

packet_count = 0

def my_WriteFile(handle, buf, count, written, overlapped):
    global packet_count
    if handle in pipe_handles:
        packet_count += 1
        data = ctypes.string_at(buf, count)
        print(f"\n[IAT HOOK WriteFile #{packet_count}] Handle={hex(handle)}, Bytes={count}", flush=True)
        print(f"  First 48 bytes hex: {data[:48].hex()}", flush=True)
        # Optional: dump full packets to disk for offline analysis.
        # Uncomment if you want the raw bytes saved -- off by default so
        # nothing sensitive gets written to disk without asking for it.
        # dump_name = f"/tmp/packet_{packet_count}.bin"
        # open(dump_name, "wb").write(data)
        # print(f"  Dumped full {count} bytes to {dump_name}", flush=True)

    res = real_WriteFile(handle, buf, count, written, overlapped)
    err = ctypes.get_last_error()
    if handle in pipe_handles:
        w_val = written.contents.value if written else 0
        print(f"  WriteFile res={res}, written={w_val}, err={err}", flush=True)
    return res

def my_ReadFile(handle, buf, count, read, overlapped):
    if handle in pipe_handles:
        print(f"\n[IAT HOOK ReadFile] Handle={hex(handle)}, Expecting {count} bytes...", flush=True)
    res = real_ReadFile(handle, buf, count, read, overlapped)
    err = ctypes.get_last_error()
    if handle in pipe_handles:
        r_val = read.contents.value if read else 0
        data = ctypes.string_at(buf, min(r_val, 64)) if r_val > 0 else b""
        print(f"  ReadFile res={res}, read={r_val}, err={err}", flush=True)
        if r_val > 0:
            print(f"  Received hex: {data.hex()}", flush=True)
    return res

cb_CreateFileW = CREATEFILEW_PROTO(my_CreateFileW)
cb_WriteFile = WRITEFILE_PROTO(my_WriteFile)
cb_ReadFile = READFILE_PROTO(my_ReadFile)

# Patch IAT
old_prot = wintypes.DWORD()

for rva, cb in [(create_iat_rva, cb_CreateFileW), (write_iat_rva, cb_WriteFile), (read_iat_rva, cb_ReadFile)]:
    p = h_mod + rva
    VirtualProtect(p, 8, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
    ctypes.c_uint64.from_address(p).value = ctypes.cast(cb, ctypes.c_void_p).value
    VirtualProtect(p, 8, old_prot.value, ctypes.byref(old_prot))

print("[+] IAT successfully hooked in _core.pyd!", flush=True)

# Point this at your own terminal64.exe -- pass it as argv[1], or edit the
# default below. Nothing broker-specific is hardcoded here.
default_path = r"C:\Program Files\MetaTrader 5\terminal64.exe"
path = sys.argv[1] if len(sys.argv) > 1 else default_path

print(f"[*] Triggering mt5.initialize(path='{path}', portable=True, timeout=6000)...", flush=True)
res = mt5.initialize(path=path, portable=True, timeout=6000)
print(f"\n[*] mt5.initialize() returned: {res}, last_error: {mt5.last_error()}", flush=True)
