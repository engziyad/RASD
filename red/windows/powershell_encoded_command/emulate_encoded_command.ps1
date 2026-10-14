<#
.SYNOPSIS
    RASD-Red · T1059.001 · powershell.exe -enc with a benign payload.
.DESCRIPTION
    Encodes Write-Output '<marker>' as UTF-16LE Base64 and runs it in a child
    powershell.exe with -NoProfile -enc. Nothing is written to disk.
    Lab use only: run through red\Invoke-RasdEmulation.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$Marker'"))
& powershell.exe -NoProfile -enc $encoded
if ($LASTEXITCODE -ne 0) { throw "powershell.exe exited with $LASTEXITCODE" }
