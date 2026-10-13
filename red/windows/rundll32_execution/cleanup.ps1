<#
.SYNOPSIS
    RASD-Red cleanup · rundll32_execution. Exit code 0 only when verified clean.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

function Get-EmulationProcess {
    # only this run's process: the marker is part of its script
    @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'rundll32.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Marker) })
}
foreach ($p in Get-EmulationProcess) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
if (@(Get-EmulationProcess).Count -eq 0) { Write-Host "[cleanup] verified: no rundll32 process with $Marker remains"; exit 0 }
Write-Warning "[cleanup] a rundll32 process with $Marker is still running"
exit 1
