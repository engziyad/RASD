<#
.SYNOPSIS
    RASD-Red · T1685.005 · wevtutil cl on a dedicated test log (writes System 104).
.DESCRIPTION
    Creates the classic event log R<hex> (R plus the marker's 8 random characters), writes one
    entry and clears it with wevtutil. Classic log names are unique on their first 8 characters,
    so the name starts with the marker's random part, not the prefix every marker shares. No existing
    log is touched. cleanup.ps1 removes the test log. Requires an elevated
    Windows PowerShell 5.1 session (New-EventLog). Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab
if (-not (Get-Command New-EventLog -ErrorAction SilentlyContinue)) {
    throw 'New-EventLog is not available: run the emulation from Windows PowerShell 5.1'
}

$LogName = 'R' + $Marker.Substring($Marker.Length - 8)
if ([System.Diagnostics.EventLog]::Exists($LogName)) { throw "event log $LogName already exists" }
New-EventLog -LogName $LogName -Source $Marker
Write-EventLog -LogName $LogName -Source $Marker -EventId 1 -EntryType Information -Message "RASD-Red test entry $Marker"
& wevtutil.exe cl $LogName
if ($LASTEXITCODE -ne 0) { throw "wevtutil.exe exited with $LASTEXITCODE" }
