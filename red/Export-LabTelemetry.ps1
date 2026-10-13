<#
.SYNOPSIS
    Export the lab telemetry the detections read (Sysmon, Security, System) to JSONL.

.DESCRIPTION
    Writes one flat JSON object per event. EventData and UserData fields become
    top-level keys, so the file uses the same field names as the rules and the test
    samples, and can go straight into:

        python rasd.py evidence --results emulation-results.json --logs lab-export.jsonl
        python rasd.py replay lab-export.jsonl
        python rasd.py doctor lab-export.jsonl

    Run it on the lab VM after Invoke-PurpleEmulation.ps1. Kerberos service tickets
    (4769) and Kerberos pre-authentication failures (4771) are logged on the domain
    controller, so for T1558.003 and T1110.003 run it there too and pass both files to
    --logs.

    Read-only: it never changes or clears a log. Works on Windows PowerShell 5.1 and 7.

.PARAMETER Since
    Export events created at or after this time. Default: two hours ago.

.PARAMETER OutFile
    Output path. Written as UTF-8 without a byte-order mark.

.PARAMETER LogName
    Logs to read. Logs that do not exist on this host are skipped with a warning.

.PARAMETER EventId
    Event IDs to keep. Default: the IDs the detections and correlations in this
    repository read.

.PARAMETER MaxEvents
    Optional cap per log: the first N events of the window (oldest first). 0 means no cap.

.EXAMPLE
    .\Export-LabTelemetry.ps1 -Since (Get-Date).AddMinutes(-30)

.EXAMPLE
    .\Export-LabTelemetry.ps1 -LogName Security -EventId 4769 -OutFile .\dc-export.jsonl
#>
[CmdletBinding()]
param(
    [datetime] $Since = (Get-Date).AddHours(-2),

    [string] $OutFile = (Join-Path $PSScriptRoot 'lab-export.jsonl'),

    [string[]] $LogName = @('Microsoft-Windows-Sysmon/Operational', 'Security', 'System'),

    [int[]] $EventId = @(1, 10, 13, 104, 1102, 4625, 4769, 4771, 7045),

    [int] $MaxEvents = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-EventXml {
    <#
    .SYNOPSIS
        Flatten one event's XML into an ordered dictionary of field -> value.
    .DESCRIPTION
        EventData and UserData fields become top-level keys with their own names, the names
        the rules read. PowerShell dictionaries ignore case, so record metadata from <System>
        is written under System_* names: Sysmon's own ProcessId and UtcTime (EventData) are
        never overwritten or renamed by the System ProcessID / time. EventData cannot replace
        the five core keys (Channel, Provider_Name, EventID, Computer, TimeCreated); a
        clashing EventData or UserData field keeps its value under <name>_EventData /
        <name>_UserData, and System 104's cleared-log name is Channel_Cleared.
    #>
    param(
        [Parameter(Mandatory)] [string] $Xml,
        [Parameter(Mandatory)] [string] $Channel
    )
    $doc = [xml]$Xml
    $record = [ordered]@{ Channel = $Channel }
    $core = @('Channel', 'Provider_Name', 'EventID', 'Computer', 'TimeCreated')
    foreach ($section in $doc.DocumentElement.ChildNodes) {
        switch ($section.LocalName) {
            'System' {
                foreach ($node in $section.ChildNodes) {
                    switch ($node.LocalName) {
                        'Provider'      { $record['Provider_Name'] = $node.GetAttribute('Name') }
                        'EventID'       { $record['EventID'] = [int]$node.InnerText }
                        'Computer'      { $record['Computer'] = $node.InnerText }
                        'TimeCreated'   { $record['TimeCreated'] = $node.GetAttribute('SystemTime') }
                        'EventRecordID' { $record['EventRecordID'] = [long]$node.InnerText }
                        'Level'         { $record['System_Level'] = $node.InnerText }
                        'Task'          { $record['System_Task'] = $node.InnerText }
                        'Opcode'        { $record['System_Opcode'] = $node.InnerText }
                        'Keywords'      { $record['System_Keywords'] = $node.InnerText }
                        'Execution' {
                            $record['System_ProcessID'] = $node.GetAttribute('ProcessID')
                            $record['System_ThreadID'] = $node.GetAttribute('ThreadID')
                        }
                        'Correlation' {
                            $activity = $node.GetAttribute('ActivityID')
                            if ($activity) { $record['System_ActivityID'] = $activity }
                            $related = $node.GetAttribute('RelatedActivityID')
                            if ($related) { $record['System_RelatedActivityID'] = $related }
                        }
                    }
                }
            }
            'EventData' {
                foreach ($data in $section.ChildNodes) {
                    if ($data.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                    $name = $data.GetAttribute('Name')
                    if (-not $name) { continue }
                    if ($core -contains $name) { $name = $name + '_EventData' }
                    $record[$name] = $data.InnerText
                }
            }
            'UserData' {
                # e.g. <LogFileCleared><SubjectUserName/>...<Channel/></LogFileCleared>
                foreach ($wrapper in $section.ChildNodes) {
                    foreach ($field in $wrapper.ChildNodes) {
                        if ($field.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                        $name = $field.LocalName
                        if ($name -eq 'Channel') { $name = 'Channel_Cleared' }          # 104: the cleared log
                        elseif ($record.Contains($name)) { $name = $name + '_UserData' }
                        $record[$name] = $field.InnerText
                    }
                }
            }
        }
    }
    return $record
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced: expose the function only

$fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
$parent = Split-Path -Parent $fullPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($fullPath, $false, $utf8NoBom)
$total = 0
try {
    foreach ($log in $LogName) {
        $filter = @{ LogName = $log; StartTime = $Since }
        if ($EventId) { $filter['Id'] = $EventId }
        $count = 0
        $failed = 0
        # -Oldest: chronological file, and -MaxEvents keeps the first N events of the window.
        # The pipeline hands over one event at a time, so memory stays flat on large logs.
        $queryArgs = @{ FilterHashtable = $filter; ErrorAction = 'Stop'; Oldest = $true }
        if ($MaxEvents -gt 0) { $queryArgs['MaxEvents'] = $MaxEvents }
        try {
            Get-WinEvent @queryArgs | ForEach-Object {
                try {
                    $record = ConvertFrom-EventXml -Xml $_.ToXml() -Channel $log
                    $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 4))
                    $count++
                }
                catch {
                    $failed++
                }
            }
            Write-Host ("[$log] $count event(s)" + $(if ($failed) { ", $failed unreadable" } else { '' }))
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
                Write-Host "[$log] no matching events since $Since"
            }
            else {
                Write-Warning "[$log] skipped after $count event(s): $($_.Exception.Message)"
            }
        }
        $total += $count
    }
}
finally {
    $writer.Dispose()
}
Write-Host "`n[+] $total event(s) written to $fullPath" -ForegroundColor Green
