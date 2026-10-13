<#
.SYNOPSIS
    RASD-Red · T1053.005 · schtasks /create with a cmd /c action in %TEMP%.
.DESCRIPTION
    Creates the task <marker>, set to run once at 23:59, whose action echoes the marker into
    %TEMP%\<marker>.txt. cleanup.ps1 deletes it. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

& schtasks.exe /create /tn $Marker /sc once /st 23:59 /f /tr "cmd /c echo $Marker > %TEMP%\$Marker.txt"
if ($LASTEXITCODE -ne 0) { throw "schtasks.exe exited with $LASTEXITCODE" }
