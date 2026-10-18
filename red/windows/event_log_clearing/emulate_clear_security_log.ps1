<#
.SYNOPSIS
    RASD-Red · T1685.005 · wevtutil cl Security with a backup first (writes Security 1102).
.DESCRIPTION
    Backs the Security log up to %TEMP%\security-before-clear-<marker>.evtx and clears it in
    one wevtutil call (cl /bu:). Refuses to run if the backup file already exists. Run it on a
    disposable lab VM whose logs are already forwarded: the opt-in -IncludeSecurityLogClear is
    required here as well as on the runner, so a direct call cannot clear the log by mistake.
    Requires an elevated session.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [switch] $IncludeSecurityLogClear
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
if (-not $IncludeSecurityLogClear) { throw 'Refusing to run without -IncludeSecurityLogClear: this step clears the Security log.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab

$backup = Join-Path $env:TEMP "security-before-clear-$Marker.evtx"
if (Test-Path -LiteralPath $backup) { throw "backup target already exists: $backup" }
& wevtutil.exe cl Security "/bu:$backup"
if ($LASTEXITCODE -ne 0) { throw "wevtutil.exe exited with $LASTEXITCODE" }
Write-Host "Security log backed up to $backup and cleared"
