<#
.SYNOPSIS
    RASD-Red · T1218.011 · rundll32 javascript: proxy execution (closes immediately).
.DESCRIPTION
    Starts rundll32.exe with javascript:"\..\mshtml,RunHTMLApplication ";var m='<marker>';close();
    and waits up to 15 seconds for it to exit. The script assigns the marker (so cleanup and
    evidence can tell this process from any other) and closes. Lab use only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [switch] $LabConfirmed
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }

$arguments = 'javascript:"\..\mshtml,RunHTMLApplication ";var m=''{0}'';close();' -f $Marker
$p = Start-Process -FilePath rundll32.exe -ArgumentList $arguments -PassThru
if (-not $p.WaitForExit(15000)) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Write-Warning 'rundll32 did not exit within 15 s and was stopped (the event was still written)'
}
