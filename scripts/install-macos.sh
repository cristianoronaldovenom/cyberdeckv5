#!/bin/sh
# OMNI installer for macOS (Homebrew).
#   ./scripts/install-macos.sh            user install (~/.local/share)
#   ./scripts/install-macos.sh --deps-only
#
# The radio trades are the weak spot here: Homebrew's aircrack-ng can capture
# but macOS gives no reliable monitor-mode vif on the built-in card, so the
# pure-Python side (wifi.crack_pure, wifi.decrypt, wifi.extract, everything
# under omni.ios, omni.brute, omni.news, omni.flip) is what actually works.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$HOME/.local/share/omni-venv"
BINDIR="$HOME/.local/bin"

if ! command -v brew >/dev/null 2>&1; then
    echo "[!] Homebrew is required: https://brew.sh" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 not found — brew install python@3.12" >&2
    exit 1
fi
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
case "$PYVER" in
    3.1[1-9]|3.[2-9][0-9]) ;;
    *) echo "[!] Python >= 3.11 required, found $PYVER" >&2; exit 1 ;;
esac

echo "[*] installing brew packages (best effort)..."
for pkg in python@3.12 nmap jadx whois hashcat john-jumbo hydra \
           aircrack-ng hcxtools hcxdumptool mdk4 libimobiledevice usbmuxd \
           rtl-sdr librtlsdr; do
    brew list "$pkg" >/dev/null 2>&1 || brew install "$pkg" \
        || echo "[!] $pkg unavailable (its trade stays degraded)"
done

if [ "${1:-}" = "--deps-only" ]; then
    echo "[+] deps done"
    exit 0
fi

echo "[*] creating venv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet "$ROOT"
# iOS control: the pair/HID/backup trade rides this
"$VENV/bin/pip" install --quiet pymobiledevice3 \
    || echo "[!] pymobiledevice3 failed; iOS control disabled"
command -v palera1n >/dev/null 2>&1 \
    || echo "[i] palera1n not found; ios.checkm8 stays report-only"

mkdir -p "$BINDIR"
printf '#!/bin/sh\nexec %s/bin/python3 -m omni.cli "$@"\n' "$VENV" \
    > "$BINDIR/omni"
chmod +x "$BINDIR/omni"
echo "[+] installed: $BINDIR/omni"
echo "[i] ensure $BINDIR is on PATH, then: omni doctor"
echo "[!] monitor mode: use a supported external adapter, or expect"
echo "    capture-only behaviour from the built-in card"
