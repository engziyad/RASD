<#
.SYNOPSIS
    RASD-Red collect · lsass_memory_access. Prints the path of every file it writes.
.DESCRIPTION
    Records the dump's path, size and SHA-256 in a small JSON file. The dump itself is never
    copied: it contains credentials.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$dump = Join-Path "$env:SystemRoot\Temp" "$Marker.dmp"
if (-not (Test-Path -LiteralPath $dump)) { Write-Warning '[collect] no dump file to record'; return }
$info = Get-Item -LiteralPath $dump
$hash = (Get-FileHash -LiteralPath $dump -Algorithm SHA256).Hash.ToLower()
$path = Join-Path $OutDir "dump-metadata-$Marker.json"
$json = ConvertTo-Json -InputObject ([ordered]@{ path = $dump; size_bytes = $info.Length; sha256 = $hash; kept = $false })
[System.IO.File]::WriteAllText($path, $json)
Write-Host "[collect] dump $Marker.dmp hashed (size and SHA-256 recorded, file not kept)"
$path
