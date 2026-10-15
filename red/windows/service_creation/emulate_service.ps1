<#
.SYNOPSIS
    RASD-Red · T1569.002 · service with a cmd.exe /c binary path (never started).
.DESCRIPTION
    Creates the service <marker> with binPath "cmd.exe /c echo <marker>" and start=demand.
    It is never started. cleanup.ps1 deletes it. Requires an elevated session. Lab use only.
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

& sc.exe create $Marker binPath= "cmd.exe /c echo $Marker" start= demand
if ($LASTEXITCODE -ne 0) { throw "sc.exe exited with $LASTEXITCODE" }
