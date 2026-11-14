#!/bin/sh
# OMNI installer for Kali / Debian / Arch.
#   sudo ./install.sh          system-wide (pipx style via venv)
#   ./install.sh --user        current user only
#   ./install.sh --deps-only   system packages, no Python install
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
MODE="${1:-}"

# macOS has its own path (Homebrew, no apt, no udev) -- hand over to it.
if [ "$(uname -s)" = "Darwin" ]; then
    exec sh "$ROOT/scripts/install-macos.sh" $MODE
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 not found -- install it first (apt install python3)" >&2
    exit 1
fi
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
case "$PYVER" in
    3.1[1-9]|3.[2-9][0-9]) ;;
    *) echo "[!] Python >= 3.11 required, found $PYVER" >&2; exit 1 ;;
esac
if ! python3 -c 'import venv' >/dev/null 2>&1; then
    echo "[!] python3-venv missing -- apt install python3-venv" >&2
    exit 1
fi

echo "[*] installing system deps..."
if command -v apt >/dev/null 2>&1; then
    SUDO=""
    [ "$(id -u)" != "0" ] && SUDO="sudo"
    $SUDO apt update || echo "[!] apt update failed; continuing with cached lists"
    # core + existing trades
    $SUDO apt install -y python3 python3-pip python3-venv adb nmap jadx \
        whois dnsutils curl wireless-tools iw \
        aircrack-ng hcxtools hcxdumptool reaver wash bully mdk4 hostapd \
        dnsmasq hashcat john hydra rtl-sdr rtl-433 fldigi \
        bluez proxmark3 libnfc-bin mfoc mfcuk v4l-utils lirc \
        libimobiledevice-utils usbmuxd ifuse \
        || echo "[!] some packages unavailable on this release; continuing"
    # regulatory DB: without it 5 GHz channels stay restricted and TX is
    # refused on most of the band
    $SUDO apt install -y wireless-regdb crda 2>/dev/null || true
    # iOS control needs pymobiledevice3 (pip, not apt)
    $SUDO apt install -y python3-pip >/dev/null 2>&1 || true

    # Kali names its metapackages differently; add the few missing tools
    if [ -d /usr/share/kali-menu ] || grep -qi kali /etc/os-release 2>/dev/null; then
        echo "[*] Kali detected -- adding attack extras"
        $SUDO apt install -y mdk4 tcpdump kismet 2>/dev/null || true
        # USB adapter: allow non-root monitor mode via NetworkManager
        printf '[keyfile]\nunmanaged-devices=none\n' \
            | $SUDO tee /etc/NetworkManager/conf.d/99-omni-monitor.conf >/dev/null
        $SUDO systemctl reload NetworkManager 2>/dev/null || true
        echo "[i] NetworkManager will leave monitor-mode setup to OMNI"
    fi
    # rockyou ships with the wordlists package
    $SUDO apt install -y wordlists 2>/dev/null || true
    if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
        $SUDO gunzip -f /usr/share/wordlists/rockyou.txt.gz
    fi
elif command -v pacman >/dev/null 2>&1; then
    SUDO=""
    [ "$(id -u)" != "0" ] && SUDO="sudo"
    $SUDO pacman -Sy --noconfirm --needed python adb nmap jadx whois curl \
        iw aircrack-ng hcxtools reaver hostapd dnsmasq hashcat john hydra \
        rtl-sdr bluez v4l-utils lirc libimobiledevice usbmuxd
fi

echo "[*] creating venv and installing OMNI..."
if [ "$MODE" = "--deps-only" ]; then
    echo "[+] system packages done; skipping the Python install"
    exit 0
fi

if [ "$MODE" = "--user" ]; then
    python3 -m venv "$HOME/.local/share/omni-venv"
    VENV="$HOME/.local/share/omni-venv"
    "$VENV/bin/pip" install --quiet "$ROOT"
    # optional iOS stack (kept optional: needs Developer Mode on the device)
    "$VENV/bin/pip" install --quiet pymobiledevice3 \
        || echo "[!] pymobiledevice3 failed to install; iOS control disabled"
    # A5-A11 only: the trust-free route. Not in apt; grab it from its repo.
    command -v palera1n >/dev/null 2>&1 \
        || echo "[i] palera1n not found; ios.checkm8 stays report-only"
    BINDIR="$HOME/.local/bin"
    mkdir -p "$BINDIR"
else
    python3 -m venv /opt/omni-venv
    /opt/omni-venv/bin/pip install --quiet "$ROOT"
    /opt/omni-venv/bin/pip install --quiet pymobiledevice3 \
        || echo "[!] pymobiledevice3 failed to install; iOS control disabled"
    BINDIR="/usr/local/bin"
fi
printf '#!/bin/sh\nexec %s/bin/python3 -m omni.cli "$@"\n' \
    "${VENV:-/opt/omni-venv}" > "$BINDIR/omni"
chmod +x "$BINDIR/omni"
# the repo launcher also works in-place from a git checkout
if [ -f "$ROOT/bin/omni" ]; then
    chmod +x "$ROOT/bin/omni" || true
fi

echo "[+] done. Run:  omni        (interactive)   omni list   omni doctor"
echo "[i] monitor mode, injection and GPIO need root: sudo omni ..."
echo "[i] omni doctor reports which radio/wireless tools this box is missing."
