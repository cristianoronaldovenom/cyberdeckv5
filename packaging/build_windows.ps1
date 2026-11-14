# Build the frozen Windows binary: dist\OMNI.exe
#
#   powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#
# The exe needs no Python on the target machine. Anything a trade shells out to
# (nmap, adb, ...) is still external, but every module degrades cleanly when a
# tool is absent, so the build always starts and always opens the menu.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Push-Location $root
try {
    python scripts/make_manifest.py
    python -m PyInstaller packaging/omni.spec --noconfirm --clean `
        --distpath dist --workpath build
} finally {
    Pop-Location
}

$exe = Join-Path $root 'dist\OMNI.exe'
if (-not (Test-Path $exe)) { throw "build failed: $exe is missing" }

# Windows Application Control (WDAC / Smart App Control) refuses a fresh
# unsigned one-file exe. Sign with the local OMNI certificate when possible.
try {
    & (Join-Path $PSScriptRoot 'sign_windows.ps1') -Exe $exe -Trust | Out-Null
    Write-Host 'signed with the local OMNI certificate'
} catch {
    Write-Host "signing skipped: $($_.Exception.Message)"
}

Write-Host "built: $exe"
Write-Host 'smoke test:'
# Application Control notices a new signature after a beat; without this the
# first smoke run can be refused as if the file were still unsigned.
Start-Sleep -Seconds 2
$smoke = & $exe --no-color list | Out-String
if ($smoke -notmatch 'OMNI') { throw 'smoke test: list produced no banner' }
Write-Host '  list ok'
$gui = & $exe --no-color gui --check | Out-String
if ($gui -notmatch 'GUI OK') { throw 'smoke test: GUI did not build' }
Write-Host ('  ' + $gui.Trim())
