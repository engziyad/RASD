<#
.SYNOPSIS
    RASD-Red · T1053.005 · Register-ScheduledTask with an inline action in $env:TEMP.
.DESCRIPTION
    Starts a child powershell.exe whose command line registers <marker>_ps with an action
    pointing to $env:TEMP\<marker>.exe (the file does not exist) and a trigger one year
    from now, so the task never runs. cleanup.ps1 unregisters it. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

# The child command line is the telemetry: keep $env:TEMP literal so it appears in Sysmon 1.
$command = "Register-ScheduledTask -TaskName $($Marker)_ps -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddYears(1)) " +
           "-Action (New-ScheduledTaskAction -Execute `$env:TEMP\$Marker.exe) | Out-Null"
& powershell.exe -NoProfile -Command $command
if ($LASTEXITCODE -ne 0) { throw "powershell.exe exited with $LASTEXITCODE" }
