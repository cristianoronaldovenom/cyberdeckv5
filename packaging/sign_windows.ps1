# OMNI - sign the built exe with a local self-signed certificate.
#
# Some machines run Device Guard / WDAC / AppLocker "signed only" policies that
# refuse a freshly built, unsigned binary. A self-signed certificate does not
# make the exe trusted by SmartScreen, but it does satisfy a policy that only
# asks "is this signed at all".
#
#   powershell -ExecutionPolicy Bypass -File packaging\sign_windows.ps1
#
# The certificate is created in CurrentUser\My and also copied into
# CurrentUser\TrustedPublisher when -Trust is passed (needs no admin).

param(
    [string]$Exe = (Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) 'dist\OMNI.exe'),
    [switch]$Trust
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Exe)) { throw "nothing to sign at $Exe" }

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq 'CN=OMNI Local Build' } | Select-Object -First 1
if (-not $cert) {
    Write-Host 'creating a local signing certificate'
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject 'CN=OMNI Local Build' -KeyUsage DigitalSignature `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(3)
}
if ($Trust) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        'TrustedPublisher', 'CurrentUser')
    $store.Open('ReadWrite')
    $store.Add($cert)
    $store.Close()
    Write-Host 'certificate added to TrustedPublisher'
}

$signed = Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert `
    -TimestampServer 'http://timestamp.digicert.com' -ErrorAction Stop
if ($signed.Status -notin 'Valid', 'UnknownError') {
    Write-Host "signature status: $($signed.Status) - retrying without timestamp"
    Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert | Out-Null
}
Write-Host "signed: $Exe"
Get-AuthenticodeSignature $Exe | Format-List Status, SignerCertificate
