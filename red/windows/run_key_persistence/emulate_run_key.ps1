<#
.SYNOPSIS
    RASD-Red · T1547.001 · HKCU Run value pointing into %LOCALAPPDATA%\Temp.
.DESCRIPTION
    Writes the value <marker> = %LOCALAPPDATA%\Temp\<marker>.exe under the current user's
    Run key. The file does not exist. cleanup.ps1 removes the value. Lab use only.
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

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $runKey -Name $Marker -Value "$env:LOCALAPPDATA\Temp\$Marker.exe" -PropertyType String -Force | Out-Null
