<#
.SYNOPSIS
    RASD-Red cleanup · powershell_encoded_command. Exit code 0 only when verified clean.
.DESCRIPTION
    The test writes nothing to disk or registry. The marker only appears inside the Base64
    payload, so cleanup rebuilds that exact payload, stops any powershell.exe still carrying it
    and verifies none is left.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '$Marker'"))
function Get-MarkerProcess {
    @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($encoded) -and $_.ProcessId -ne $PID })
}
foreach ($p in Get-MarkerProcess) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
if (@(Get-MarkerProcess).Count -eq 0) { Write-Host '[cleanup] verified: nothing persisted'; exit 0 }
Write-Warning '[cleanup] a marker process is still running'
exit 1
