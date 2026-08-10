# Firebreak installer for Windows.
#
#   irm https://raw.githubusercontent.com/ghostpsalm/Firebreak/main/install/install.ps1 | iex
#
# Installs the latest release to %ProgramFiles%\Firebreak and adds a Start
# Menu shortcut. Firebreak requires administrator rights by design — every
# read in its evidence loop (Security log, audit policy, WFP filter table) is
# admin-bound — so the shortcut inherits the executable's own manifest and
# prompts via UAC when launched.
#
# The release signature is verified when minisign is available; when it is
# not, the install continues over HTTPS from GitHub but says so and prints
# the SHA-256 to compare against the release page.
#
#   -Prefix <dir>   install directory (default %ProgramFiles%\Firebreak)
#   -NoShortcut     skip the Start Menu shortcut
#   -Uninstall      remove the install directory and the shortcut

[CmdletBinding()]
param(
    [string] $Prefix = (Join-Path $env:ProgramFiles 'Firebreak'),
    [switch] $NoShortcut,
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo   = 'ghostpsalm/Firebreak'
$Asset  = 'firebreak.exe'
# Same key pinned in the binary as TRUSTED_PUBLIC_KEY.
$PubKey = 'RWQqalkBegJ2f0SS5E5JvOJX6WnuZfhaCKYiSdOrmugiiZoufxFMTplC'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this in an elevated PowerShell — it installs to $Prefix. (Start menu -> Windows PowerShell -> Run as administrator)"
    }
}

$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Firebreak.lnk'

Assert-Admin

if ($Uninstall) {
    if (Test-Path $shortcut) { Remove-Item $shortcut -Force }
    if (Test-Path $Prefix)   { Remove-Item $Prefix -Recurse -Force }
    Write-Host "Removed Firebreak. Collected data in %ProgramData%\firebreak was left alone."
    return
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("firebreak-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $base = "https://github.com/$Repo/releases/latest/download"
    Write-Host 'Downloading the latest Firebreak...'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $exe = Join-Path $tmp $Asset
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$Asset" -OutFile $exe
    $sig = "$exe.minisig"
    try { Invoke-WebRequest -UseBasicParsing -Uri "$base/$Asset.minisig" -OutFile $sig } catch { $sig = $null }

    $minisign = Get-Command minisign -ErrorAction SilentlyContinue
    if ($minisign -and $sig) {
        Write-Host 'Verifying the signature...'
        $pub = Join-Path $tmp 'firebreak.pub'
        Set-Content -Path $pub -Value @('untrusted comment: firebreak', $PubKey) -Encoding ascii
        & $minisign.Source verify -p $pub -x $sig -m $exe | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "The download did NOT verify against Firebreak's signing key - refusing to install it. Do not run the downloaded file."
        }
        Write-Host 'Signature verified.'
    } else {
        Write-Host ''
        Write-Host 'NOT VERIFIED: minisign is not installed, so the release signature was'
        Write-Host 'not checked. The download came over HTTPS from GitHub.'
        $hash = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLower()
        Write-Host "SHA-256 of what was downloaded - compare it against the release page:"
        Write-Host "  $hash"
        Write-Host ''
    }

    New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    $target = Join-Path $Prefix $Asset
    Copy-Item $exe $target -Force
    Write-Host "Installed $target"

    if (-not $NoShortcut) {
        $ws = New-Object -ComObject WScript.Shell
        $lnk = $ws.CreateShortcut($shortcut)
        $lnk.TargetPath = $target
        $lnk.WorkingDirectory = $Prefix
        $lnk.Description = 'Firewall rule-usage auditor - observe first, enforce with confidence'
        $lnk.Save()
        Write-Host "Added a Start Menu shortcut."
    }

    Write-Host ''
    Write-Host 'Firebreak is installed. It runs elevated by design, so launching it'
    Write-Host 'prompts for administrator rights.'
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
