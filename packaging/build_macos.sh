#!/bin/sh
# Build the frozen macOS binary and app bundle: dist/OMNI, dist/OMNI.app
#
#   bash packaging/build_macos.sh
#
# Must run on macOS (PyInstaller does not cross-compile). The bundle is
# ad-hoc signed so Gatekeeper accepts a local double-click.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

python3 scripts/make_manifest.py
python3 -m PyInstaller packaging/omni.spec --noconfirm --clean \
    --distpath dist --workpath build

for target in dist/OMNI dist/OMNI.app; do
    [ -e "$target" ] || continue
    codesign --force --deep --sign - "$target" 2>/dev/null || true
done

echo "built: dist/OMNI"
echo "install: cp -R dist/OMNI.app /Applications/"
