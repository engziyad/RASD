<#
.SYNOPSIS
    RASD-Red collect · powershell_encoded_command. Prints the path of every file it writes.
.DESCRIPTION
    Saves the 4104 script blocks that contain the marker (the decoded payload) as JSON.
    Writes nothing when script block logging is off - that is itself a finding.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddMinutes(-30)
try {
    $blocks = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } -ErrorAction Stop |
        Where-Object { $_.Message -match [regex]::Escape($Marker) })
} catch {
    Write-Warning "[collect] no 4104 events: $($_.Exception.Message)"
    return
}
if ($blocks.Count -eq 0) { Write-Warning '[collect] script block logging captured nothing for the marker'; return }
$path = Join-Path $OutDir 'scriptblock-4104.json'
$json = ConvertTo-Json -InputObject @($blocks | Select-Object TimeCreated, Id, MachineName, Message) -Depth 3
[System.IO.File]::WriteAllText($path, $json)
$path
