#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Recreates netsh portproxy rules that forward Wazuh ports from Windows to WSL2.

.DESCRIPTION
    The WSL2 IP address in NAT mode is dynamic. This script:
      1. verifies it is running with administrator rights;
      2. detects the current WSL2 IP via `wsl hostname -I`;
      3. removes ALL existing portproxy rules;
      4. adds rules for ports 443, 1514, 1515 and 55000;
      5. prints the resulting rule list.
    The script is idempotent: running it again produces the same result.

.PARAMETER LogPath
    Path to the log file.

.PARAMETER ListenAddress
    Address the host listens on. Defaults to 0.0.0.0 so that the agent on VMnet1
    can connect to 192.168.230.1.

.EXAMPLE
    .\update-portproxy.ps1
#>

[CmdletBinding()]
param(
    [string]$LogPath       = 'D:\SOC-Lab\logs\portproxy.log',
    [string]$ListenAddress = '0.0.0.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Ports = @(443, 1514, 1515, 55000)

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        Add-Content -Path $LogPath -Value $line -Encoding UTF8
    }
    catch {
        Write-Host "Failed to write to the log: $($_.Exception.Message)"
    }
}

# Log directory
try {
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
}
catch {
    Write-Host "Failed to create the log directory: $($_.Exception.Message)"
}

Write-Log '=== Starting update-portproxy.ps1 ==='

# Administrator check (duplicates #Requires in case of dot-sourcing)
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log 'Administrator rights are required.' 'ERROR'
    exit 1
}

# Detect the WSL2 IP
try {
    $raw = & wsl.exe hostname -I 2>&1 | Out-String
    # wsl.exe may return UTF-16 output containing null characters
    $raw = $raw -replace "`0", ''
    $wslIp = ($raw -split '\s+' |
        Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } |
        Select-Object -First 1)
}
catch {
    Write-Log "Failed to run wsl.exe: $($_.Exception.Message)" 'ERROR'
    exit 2
}

if (-not $wslIp) {
    Write-Log 'Could not determine the WSL2 IP. Make sure the distribution is running.' 'ERROR'
    exit 2
}
Write-Log "Current WSL2 IP: $wslIp"

# Remove all existing rules
Write-Log 'Removing all existing portproxy rules (netsh interface portproxy reset).'
& netsh.exe interface portproxy reset | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Log "netsh reset failed with exit code $LASTEXITCODE" 'ERROR'
    exit 3
}

# Add new rules
foreach ($port in $Ports) {
    Write-Log "Adding rule: ${ListenAddress}:$port -> ${wslIp}:$port"
    & netsh.exe interface portproxy add v4tov4 `
        listenaddress=$ListenAddress listenport=$port `
        connectaddress=$wslIp connectport=$port | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Failed to add the rule for port $port (exit code $LASTEXITCODE)" 'ERROR'
        exit 4
    }
}

# Final rule list
Write-Log 'Resulting portproxy rules:'
$rules = & netsh.exe interface portproxy show all | Out-String
$rules.TrimEnd() -split "`r?`n" | ForEach-Object {
    if ($_.Trim()) { Write-Log $_ }
}
Write-Host ''
Write-Host $rules

Write-Log '=== Finished successfully ==='
exit 0
