<#
.SYNOPSIS
    RASD-Red collect · run_key_persistence. Prints the path of every file it writes.
.DESCRIPTION
    Saves only the marker value (name, data, key) - never the user's other Run entries.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$item = Get-ItemProperty -Path $runKey -Name $Marker -ErrorAction SilentlyContinue
if (-not $item) { Write-Warning "[collect] value $Marker not found"; return }
$data = $item.$Marker
$path = Join-Path $OutDir "run-value-$Marker.json"
$json = ConvertTo-Json -InputObject ([ordered]@{ key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'; name = $Marker; data = $data })
[System.IO.File]::WriteAllText($path, $json)
$path
