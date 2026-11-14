# OMNI - Windows installer: build, install and make the shortcuts.
#
#   powershell -ExecutionPolicy Bypass -File packaging\install_windows.ps1
#
# The binary goes to %LOCALAPPDATA%\OMNI (stable, survives moving or deleting
# the checkout) and Desktop + Start Menu shortcuts are created. A double-click
# opens the goal menu.
#
# Kept pure ASCII: Windows PowerShell may read a BOM-less script in the OEM
# code page, and one em dash is enough to break parsing there.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$exe = Join-Path $root 'dist\OMNI.exe'

if (-not (Test-Path $exe)) {
    Write-Host "no $exe - building it first"
    & (Join-Path $PSScriptRoot 'build_windows.ps1')
}
if (-not (Test-Path $exe)) { throw "build failed: $exe is missing" }

$target = Join-Path $env:LOCALAPPDATA 'Cyberdeck'
New-Item -ItemType Directory -Path $target -Force | Out-Null
$installed = Join-Path $target 'Cyberdeck.exe'

# close a running dashboard so the update can replace it; retry once after
Get-Process Cyberdeck -ErrorAction SilentlyContinue | Stop-Process -Force `
    -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 600
try {
    Copy-Item $exe $installed -Force
} catch {
    Start-Sleep -Seconds 2
    Copy-Item $exe $installed -Force
}
Write-Host "installed: $installed"

# Device Guard / WDAC policies that want signed binaries refuse an unsigned
# build, so sign with a local certificate when one can be made.
try {
    & (Join-Path $PSScriptRoot 'sign_windows.ps1') -Exe $installed -Trust |
        Out-Null
    Write-Host 'signed with the local OMNI certificate'
} catch {
    Write-Host "signing skipped: $($_.Exception.Message)"
}

$shell = New-Object -ComObject WScript.Shell
$places = @(
    [Environment]::GetFolderPath('Desktop'),
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs')
)
foreach ($place in $places) {
    if (-not (Test-Path $place)) { continue }

    # one universal shortcut only: remove every older name and every extra
    # variant so the desktop is not a wall of icons
    foreach ($old in @('OMNI.lnk', 'OMNI Dashboard.lnk', 'OMNI One-Click.lnk',
                       'Cyberdeck Dashboard.lnk',
                       'Cyberdeck One-Click.lnk', 'CyberDeck.lnk',
                       'CyberDeck Dashboard.lnk')) {
        $legacy = Join-Path $place $old
        if (Test-Path $legacy) { Remove-Item $legacy -Force }
    }

    $link = Join-Path $place 'Cyberdeck.lnk'
    $shortcut = $shell.CreateShortcut($link)
    $shortcut.TargetPath = $installed
    $shortcut.WorkingDirectory = $target
    $shortcut.Description = 'Cyberdeck - click a goal, it runs'
    $shortcut.IconLocation = "$installed,0"
    $shortcut.Save()
    Write-Host "shortcut: $link"
}

Write-Host ''
Write-Host 'Done. Double-click "Cyberdeck" for the goal cards, or from a shell:'
Write-Host ('  "' + $installed + '" goal wifi-attack')
Write-Host ('  "' + $installed + '" goals')
Write-Host ('  "' + $installed + '" doctor')
Write-Host ''
Write-Host 'External tools (nmap, adb, hashcat...) are optional; install what a'
Write-Host 'trade needs with:  omni setup   -- see packaging/README.md.'
