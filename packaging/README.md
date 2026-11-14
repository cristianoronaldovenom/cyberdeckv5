# Frozen builds

One PyInstaller definition (`omni.spec`) produces the Windows `OMNI.exe` and
the macOS `OMNI` binary. The launcher re-encodes the console to UTF-8, opens
the plain goal menu on a double-click, and keeps crashes readable.

## Windows

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
powershell -ExecutionPolicy Bypass -File packaging\install_windows.ps1
```

`build_windows.ps1` regenerates the module manifest, builds `dist\OMNI.exe`
and smoke-tests it. `install_windows.ps1` copies it to
`%LOCALAPPDATA%\Cyberdeck\Cyberdeck.exe` and creates one universal
`Cyberdeck` shortcut on the Desktop and Start Menu (older OMNI and extra
Cyberdeck shortcut names are removed). The shortcut opens the goal-card
window; each card shows READY / NEEDS SETUP before anything runs.

The build is signed with a local certificate when possible: Windows
Application Control (WDAC / Smart App Control) refuses a freshly written
unsigned one-file exe. The same certificate is trusted on this machine by
`sign_windows.ps1 -Trust`.

## macOS

```sh
bash packaging/build_macos.sh
```

The Mach-O build has to be made on a Mac.

## What is bundled, and what is not

Bundled: every Python module, `assets/` (KeeLoq manufacturer keys, sample
`.sub` files) and `data/` (sample Flipper captures, clone state). The module
manifest exists because a frozen one-file build has no package directories for
the registry to walk â€” run `python scripts/make_manifest.py` whenever a module
file is added or removed; `tests/test_graceful.py` fails when it is stale.

Not bundled: external binaries (`nmap`, `adb`, `aircrack-ng`, `hashcat`,
`pymobiledevice3`â€¦). They remain optional. On a tool-less host every module
degrades with a clear message and the exe still exits 0, or the module reports
its own empty result. Install them with:

```powershell
OMNI.exe setup                 # everything missing, via winget / pip
OMNI.exe setup nmap adb        # just these
OMNI.exe doctor                # readiness matrix, never fails
```

Linux-only wireless tools can also install inside WSL, but a USB adapter has
to be passed through (`usbipd list`, then `usbipd attach --wsl --busid <id>`)
before `hostapd`/`airmon-ng` see it. Windows' own `netsh` powers AP scanning,
link status and joining without any adapter passthrough.

