<#
.SYNOPSIS
    RASD-Red cleanup · scheduled_task_creation. Exit code 0 only when verified clean.
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)

$tasks = @($Marker, "$($Marker)_ps")
foreach ($name in $tasks) {
    & schtasks.exe /delete /tn $name /f 2>$null | Out-Null
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
$file = Join-Path $env:TEMP "$Marker.txt"
if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
Write-Host "[cleanup] removed $($tasks -join ', ')"

$left = @($tasks | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue })
if ($left.Count -eq 0 -and -not (Test-Path -LiteralPath $file)) { Write-Host '[cleanup] verified: no marker task remains'; exit 0 }
Write-Warning "[cleanup] still present: $($left -join ', ')"
exit 1
