# wine-mt5-ipc-patch

A runtime patch that fixes `MetaTrader5.initialize()` hanging for 30 seconds
and failing with `(-10005, 'IPC timeout')` when the official MetaQuotes
`MetaTrader5` Python package is run under **Wine on Linux**.

If you've hit this error and found forum posts insisting "MT5 Python just
doesn't work under Wine, use Docker / Windows Server instead" — it isn't a
Wine limitation. It's a state-machine deadlock inside MetaTrader5's own
compiled extension, and it can be patched in memory with no changes to any
signed binary.

Full write-up (the reverse-engineering process, disassembly, and how this
was found): **[Poverty Inspired Me to Fix a "Wine Can't Do This" Timeout](https://thetinkerhouse.substack.com/p/wine-cant-do-this)**

## The problem, in short

- `MetaTrader5.initialize()` calls into a bundled C extension
  (`_core.cp311-win_amd64.pyd`) that talks to the running `terminal64.exe`
  over a Windows Named Pipe.
- On every poll it sends opcode `0x6d` ("status query") and expects the
  terminal to eventually report **state 2** (`STATUS_READY`) before
  `initialize()` returns `True`.
- On a fresh headless boot (markets closed, or before any symbol has been
  subscribed), the terminal sits in **state 1** (`STATUS_INITIALIZING`)
  indefinitely — because subscribing a symbol normally happens *after*
  `initialize()` returns. That's the deadlock: the client waits on the
  terminal, and the terminal waits on the client.
- Wine's Named Pipe implementation is not at fault — traffic sniffing shows
  clean, error-free packets on both sides the entire time.

## The fix

`patch_wine_mt5.py` hooks `ReadFile` in the extension's Import Address
Table (IAT) and, only for the specific 12-byte status-reply packet
(opcode `0x6d`), rewrites the status byte from `0x01` to `0x02` before it
reaches the caller. That's the entire patch — no disk writes, no
modification of any signed file, and it only touches traffic on this one
opcode.

Import it **before** you import `MetaTrader5`:

```python
import patch_wine_mt5   # must come first
import MetaTrader5 as mt5

mt5.initialize(path=r"C:\Program Files\MetaTrader 5\terminal64.exe", portable=True)
# now returns in ~0.02s instead of timing out at 30s
```

## Files

- **`patch_wine_mt5.py`** — the fix. Import it before `MetaTrader5` and it
  applies automatically.
- **`dump_core_traffic.py`** — the diagnostic tool used to find this in the
  first place. It hooks the same three IAT entries (`CreateFileW`,
  `WriteFile`, `ReadFile`) and prints every packet crossing the pipe. Run
  it standalone against your own `terminal64.exe` if you're debugging a
  different MT5 build where offsets or opcodes have shifted:

  ```
  wine python.exe dump_core_traffic.py "C:\Program Files\MetaTrader 5\terminal64.exe"
  ```

- **`examples/bridge_server.py`** — a generalized version of a real RPyC
  bridge that loads the patch and exposes `MetaTrader5` over a local
  socket, so a native Linux process can drive it. Included to show the
  patch actually being used in a service, not as a drop-in production
  script — add your own retry/health-check logic and process supervision
  (systemd, etc.) around it.

## Requirements

- Linux with Wine 9.0+ (tested on Ubuntu 24.04)
- The official `MetaTrader5` PyPI package, installed inside the Wine
  prefix's Windows Python (not the Linux system Python)
- For `examples/bridge_server.py`: `rpyc`, installed the same way

## Notes and disclaimer

- This targets the **client-side IPC handshake only**. It doesn't touch
  order execution, account data, or anything broker-related.
- The IAT offsets in `patch_wine_mt5.py` and `dump_core_traffic.py` are
  specific to `_core.cp311-win_amd64.pyd` from MetaTrader5 terminal build
  6230. If your installed build ships a different `_core*.pyd`, re-run
  `dump_core_traffic.py` against it and use a PE parser (e.g. `pefile`) to
  confirm the current `CreateFileW` / `WriteFile` / `ReadFile` IAT RVAs
  before relying on the hardcoded values.
- Not affiliated with or endorsed by MetaQuotes or any broker. Use at your
  own risk — if you rely on this in anything production-critical, add your
  own guard/log around the patch so a future MT5 update changing the
  opcode or offsets fails loudly instead of silently.
- MIT licensed — see `LICENSE`.
