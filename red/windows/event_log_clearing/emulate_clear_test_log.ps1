<#
.SYNOPSIS
    RASD-Red · T1070.001 · wevtutil cl on a dedicated test log (writes System 104).
.DESCRIPTION
    Creates the classic event log R<hex> (R plus the marker's 8 random characters), writes one
    entry and clears it with wevtutil. Classic log names are unique on their first 8 characters,
    so a name starting with 'purplelab' would collide with any leftover test log. No existing
    log is touched. cleanup.ps1 removes the test log. Requires an elevated
    Windows PowerShell 5.1 session (New-EventLog). Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
if (-not (Get-Command New-EventLog -ErrorAction SilentlyContinue)) {
    throw 'New-EventLog is not available: run the emulation from Windows PowerShell 5.1'
}

$LogName = 'R' + $Marker.Substring(10)
if ([System.Diagnostics.EventLog]::Exists($LogName)) { throw "event log $LogName already exists" }
New-EventLog -LogName $LogName -Source $Marker
Write-EventLog -LogName $LogName -Source $Marker -EventId 1 -EntryType Information -Message "RASD-Red test entry $Marker"
& wevtutil.exe cl $LogName
if ($LASTEXITCODE -ne 0) { throw "wevtutil.exe exited with $LASTEXITCODE" }
