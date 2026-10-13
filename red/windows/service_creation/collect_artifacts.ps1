<#
.SYNOPSIS
    RASD-Red collect · service_creation. Prints the path of every file it writes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$qc = & sc.exe qc $Marker 2>&1
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Marker"
$values = if (Test-Path -LiteralPath $key) {
    Get-ItemProperty -LiteralPath $key | Select-Object ImagePath, Start, Type, ObjectName, DisplayName
} else { $null }
$path = Join-Path $OutDir "service-$Marker.json"
$json = ConvertTo-Json -InputObject ([ordered]@{ sc_qc = @($qc | ForEach-Object { "$_" }); registry = $values }) -Depth 4
[System.IO.File]::WriteAllText($path, $json)
$path
