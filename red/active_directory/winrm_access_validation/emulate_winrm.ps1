<#
.SYNOPSIS
    RASD-Red · T1021.006 · one harmless remote command over WinRM.
.DESCRIPTION
    Runs Invoke-Command against -Target with the current credentials. The remote script
    block only returns the target's hostname and the marker. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9.\-]+$')] [string] $Target
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

Invoke-Command -ComputerName $Target -ScriptBlock { param($m) "$env:COMPUTERNAME $m" } -ArgumentList $Marker
