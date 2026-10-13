<#
.SYNOPSIS
    RASD-Red collect · scheduled_task_creation. Prints the path of every file it writes.
.DESCRIPTION
    Exports the XML definition of both marker tasks before cleanup deletes them.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
foreach ($name in @($Marker, "$($Marker)_ps")) {
    if (-not (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
        Write-Warning "[collect] task $name not found"
        continue
    }
    $xml = Export-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($xml) {
        $path = Join-Path $OutDir "$name.xml"
        [System.IO.File]::WriteAllText($path, $xml)
        $path
    } else {
        Write-Warning "[collect] task $name not found"
    }
}
