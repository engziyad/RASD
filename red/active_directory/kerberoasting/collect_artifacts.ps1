<#
.SYNOPSIS
    RASD-Red collect · kerberoasting. Prints the path of every file it writes.
.DESCRIPTION
    Saves klist output for the current logon session (service tickets and encryption types).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern('^purplelab_[0-9a-f]{8}$')] [string] $Marker,
    [Parameter(Mandatory)] [string] $OutDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # the runner's 'Stop' is inherited; native stderr must not throw (Windows PowerShell 5.1)
$out = & klist.exe 2>&1
$path = Join-Path $OutDir 'klist.txt'
[System.IO.File]::WriteAllText($path, (@($out | ForEach-Object { "$_" }) -join [Environment]::NewLine))
$path
