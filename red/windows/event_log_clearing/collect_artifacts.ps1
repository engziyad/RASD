<#
.SYNOPSIS
    RASD-Red collect · event_log_clearing. Prints the path of every file it writes.
.DESCRIPTION
    Saves the System 104 record for the test log and any Security 1102 record from the last
    30 minutes as JSON.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$since = (Get-Date).AddMinutes(-30)
$records = @()
$records += @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = $since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match [regex]::Escape('R' + $Marker.Substring(10)) })
$records += @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = $since } -ErrorAction SilentlyContinue)
if ($records.Count -eq 0) { Write-Warning '[collect] no 104 or 1102 record found'; return }
$path = Join-Path $OutDir 'log-clear-records.json'
$json = ConvertTo-Json -InputObject @($records | Select-Object TimeCreated, Id, LogName, ProviderName, MachineName, Message) -Depth 3
[System.IO.File]::WriteAllText($path, $json)
$path
