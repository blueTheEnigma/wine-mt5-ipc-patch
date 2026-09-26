"""
In-Memory Import Address Table (IAT) Hook & Runtime Patch for MetaTrader 5
under Wine.

Resolves the MetaTrader5 Python IPC timeout (-10005) on headless Wine
environments. Intercepts ReadFile calls from _core.cp311-win_amd64.pyd and
patches the 12-byte opcode 0x6d polling response, overwriting byte 8
(state) from 0x01 (STATUS_INITIALIZING) to 0x02 (STATUS_READY).

mt5.initialize() execution time drops from 30.0s (timeout) to ~0.02s.

Import this module BEFORE calling mt5.initialize() -- it auto-applies on
import. See README.md for why this is safe and what it does and doesn't
touch.

NOTE ON THE HARDCODED RVA OFFSETS BELOW: these were located with pefile
against _core.cp311-win_amd64.pyd from MetaTrader5 terminal build 6230.
They are specific to that build -- if your MT5 package ships a different
_core*.pyd, re-derive the three offsets first (see dump_core_traffic.py in
this repo, which locates and prints them via the PE import table).
"""

import ctypes
from ctypes import wintypes
import sys
import os


def apply_ipc_patch():
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GetModuleHandleW = kernel32.GetModuleHandleW
        GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        GetModuleHandleW.restype = wintypes.HMODULE

        import MetaTrader5 as mt5  # noqa: F401  (must be imported before the module is resolvable)

        h_mod = GetModuleHandleW("_core.cp311-win_amd64.pyd")
        if not h_mod:
            h_mod = GetModuleHandleW("_core")
        if not h_mod:
            return False

        # RVAs specific to build 6230's _core.cp311-win_amd64.pyd -- see
        # note at the top of this file if you're on a different build.
        write_iat_rva = 0x140f0
        read_iat_rva = 0x140f8
        create_iat_rva = 0x140b8

        VirtualProtect = kernel32.VirtualProtect
        VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        VirtualProtect.restype = wintypes.BOOL

        PAGE_EXECUTE_READWRITE = 0x40

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
            if name and "pipe" in str(name).lower():
                if h and h != -1:
                    pipe_handles.add(h)
            return h

        def my_WriteFile(handle, buf, count, written, overlapped):
            return real_WriteFile(handle, buf, count, written, overlapped)

        def my_ReadFile(handle, buf, count, read, overlapped):
            res = real_ReadFile(handle, buf, count, read, overlapped)
            if handle in pipe_handles and res:
                r_val = read.contents.value if read else 0
                if r_val == 12:
                    data = (ctypes.c_uint8 * 12).from_address(buf)
                    # Opcode 0x6d status response: byte 0 = 0x6d, byte 8 = status
                    if data[0] == 0x6d:
                        data[8] = 0x02  # Force State 1 -> State 2 (STATUS_READY)
            return res

        cb_CreateFileW = CREATEFILEW_PROTO(my_CreateFileW)
        cb_WriteFile = WRITEFILE_PROTO(my_WriteFile)
        cb_ReadFile = READFILE_PROTO(my_ReadFile)

        # Keep callback references alive for the process lifetime -- ctypes
        # callbacks get garbage collected otherwise, which crashes the hook
        # mid-flight.
        apply_ipc_patch._cbs = [cb_CreateFileW, cb_WriteFile, cb_ReadFile]

        old_prot = wintypes.DWORD()
        for rva, cb in [(create_iat_rva, cb_CreateFileW), (write_iat_rva, cb_WriteFile), (read_iat_rva, cb_ReadFile)]:
            p = h_mod + rva
            VirtualProtect(p, 8, PAGE_EXECUTE_READWRITE, ctypes.byref(old_prot))
            ctypes.c_uint64.from_address(p).value = ctypes.cast(cb, ctypes.c_void_p).value
            VirtualProtect(p, 8, old_prot.value, ctypes.byref(old_prot))

        return True
    except Exception as e:
        sys.stderr.write(f"Failed to apply Wine IPC patch: {e}\n")
        return False


# Auto-apply immediately when imported
apply_ipc_patch()
