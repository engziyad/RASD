<#
.SYNOPSIS
    RASD-Red · T1021.006 · one harmless remote command over WinRM.
.DESCRIPTION
    Runs Invoke-Command against -Target with the current credentials. The remote script
    block echoes the target's hostname and the marker through cmd.exe. Lab use only: the lab
    guard checks this machine, not -Target, so name a VM of your lab domain only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9.\-]+$')] [string] $Target
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab

# cmd.exe makes the session host start a child process: the telemetry the WinRM rule reads
Invoke-Command -ComputerName $Target -ScriptBlock { param($m) cmd.exe /c "echo $env:COMPUTERNAME $m" } -ArgumentList $Marker
