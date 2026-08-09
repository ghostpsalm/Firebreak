# firebreak-collect.ps1 — offline evidence collector
#
# Run this ELEVATED on the device you want to audit, then open the produced
# firebreak-export-<HOST>-<stamp>.zip on your analysis machine via
# Firebreak → Settings → "Import Firebreak export…".
#
# It only READS: firewall rules, network profiles, and the Security event
# log (connection-audit events 5156/5157). Nothing on the device is changed.
# Note: if connection auditing was never enabled on this device, there will
# be no events to collect — enable it first and come back later:
#   auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
#   wevtutil sl Security /ms:536870912

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script elevated (Security log access requires it)."
    exit 1
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$work  = Join-Path $env:TEMP "firebreak-collect-$PID"
$out   = Join-Path ([Environment]::GetFolderPath('Desktop')) "firebreak-export-$env:COMPUTERNAME-$stamp.zip"
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "[1/4] Enumerating firewall rules..."
$apps = @{};  Get-NetFirewallApplicationFilter -All | ForEach-Object { $apps[$_.InstanceID] = $_.Program }
$ports = @{}; Get-NetFirewallPortFilter -All | ForEach-Object {
    $ports[$_.InstanceID] = @{
        Protocol   = [string]$_.Protocol
        LocalPort  = (@($_.LocalPort)  -join ',')
        RemotePort = (@($_.RemotePort) -join ',')
    }
}
$svcs = @{};  Get-NetFirewallServiceFilter -All | ForEach-Object { $svcs[$_.InstanceID] = [string]$_.Service }
$addrs = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $addrs[$_.InstanceID] = (@($_.RemoteAddress) -join ',') }
$rules = Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore | ForEach-Object {
    $p = $ports[$_.InstanceID]
    [pscustomobject]@{
        Name          = $_.Name
        DisplayName   = $_.DisplayName
        Description   = $_.Description
        Enabled       = [string]$_.Enabled
        Direction     = [string]$_.Direction
        Action        = [string]$_.Action
        Profile       = [string]$_.Profile
        Group         = $_.Group
        Program       = $apps[$_.InstanceID]
        Protocol      = $p.Protocol
        LocalPort     = $p.LocalPort
        RemotePort    = $p.RemotePort
        Service       = $svcs[$_.InstanceID]
        RemoteAddress = $addrs[$_.InstanceID]
        PolicyStoreSource     = [string]$_.PolicyStoreSource
        PolicyStoreSourceType = [string]$_.PolicyStoreSourceType
    }
}
ConvertTo-Json -InputObject @($rules) -Compress -Depth 3 | Set-Content -Encoding UTF8 (Join-Path $work "rules.json")

Write-Host "[2/4] Reading interface profiles..."
$profiles = @{}
Get-NetConnectionProfile | ForEach-Object {
    $cat = [string]$_.NetworkCategory
    if ($cat -eq 'DomainAuthenticated') { $cat = 'Domain' }
    $profiles["$($_.InterfaceIndex)"] = $cat
}
ConvertTo-Json -InputObject @{ iface_profiles = $profiles } -Compress | Set-Content -Encoding UTF8 (Join-Path $work "context.json")

Write-Host "[3/4] Exporting Security events 5156/5157 (this can take a while)..."
$evtx = Join-Path $work "events.evtx"
if (Test-Path $evtx) { Remove-Item $evtx }
& "$env:SystemRoot\System32\wevtutil.exe" epl Security $evtx "/q:*[System[(EventID=5156 or EventID=5157)]]"
if ($LASTEXITCODE -ne 0) { Write-Error "wevtutil export failed"; exit 1 }

$manifest = @{
    schema            = 1
    hostname          = $env:COMPUTERNAME
    os                = (Get-CimInstance Win32_OperatingSystem).Caption
    collected_at      = (Get-Date).ToUniversalTime().ToString("o")
    firebreak_version = "ps1"
    collector         = "ps1"
}
ConvertTo-Json -InputObject $manifest -Compress | Set-Content -Encoding UTF8 (Join-Path $work "manifest.json")

Write-Host "[4/4] Compressing bundle..."
if (Test-Path $out) { Remove-Item $out }
Compress-Archive -Path (Join-Path $work "*") -DestinationPath $out
Remove-Item -Recurse -Force $work

Write-Host ""
Write-Host "Done: $out"
Write-Host "Open it on your analysis machine: Firebreak -> Settings -> Import Firebreak export..."
