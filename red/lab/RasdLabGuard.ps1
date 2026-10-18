<#
.SYNOPSIS
    RASD lab guard: refuse to run an offensive test anywhere but a machine its owner marked as a lab.

.DESCRIPTION
    -LabConfirmed is a typed acknowledgement; it cannot tell a lab VM from a work laptop. This
    guard checks the machine itself, so a script copied or run by mistake on a corporate host
    stops before it does anything:

      1. RASD_LAB_HOST, a machine-level environment variable, must equal this computer's name.
         It is set once, on the lab VM, by its owner - never on a work machine:
             [Environment]::SetEnvironmentVariable('RASD_LAB_HOST', $env:COMPUTERNAME, 'Machine')
      2. If the computer is joined to a domain, that domain must be listed in RASD_LAB_DOMAINS
         (machine-level, comma-separated), and every listed domain must end in a lab or
         reserved suffix (.lab .test .example .invalid .localhost .local .internal .lan
         .home.arpa). That keeps a public company domain out; it cannot tell a lab corp.local
         from a real one (.local, .lan and .internal are common on company networks too), so
         the marking in check 1 is what matters:
             [Environment]::SetEnvironmentVariable('RASD_LAB_DOMAINS', 'lab.local', 'Machine')
      3. A workgroup computer (no domain) passes with check 1 alone; the Active Directory tests
         need a lab domain anyway.

    Machine-level variables are read from the registry, so a variable set only in the current
    session (or inherited from a parent shell) does not count.

    Dot-source this file and call Assert-RasdLab after the -LabConfirmed check.
#>

Set-StrictMode -Version Latest

$script:RasdLabSuffixes = @('.lab', '.test', '.example', '.invalid', '.localhost', '.local', '.internal', '.lan', '.home.arpa')

function Get-RasdMachineVariable([string] $Name) {
    $value = [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Machine)
    if ($null -eq $value) { return '' }
    return $value.Trim()
}

function Get-RasdLabProblems {
    <# Returns the reasons this host is not a confirmed lab; an empty list means it is one. #>
    [OutputType([string[]])]
    param()
    $problems = [System.Collections.Generic.List[string]]::new()
    $onWindows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
    if (-not $onWindows) {
        $problems.Add('not Windows: the RASD Windows and Active Directory tests run only on a Windows lab VM')
        return $problems.ToArray()
    }

    $computer = $env:COMPUTERNAME
    $labHost = Get-RasdMachineVariable 'RASD_LAB_HOST'
    if (-not $labHost) {
        $problems.Add("machine variable RASD_LAB_HOST is not set. On the lab VM only, as administrator: [Environment]::SetEnvironmentVariable('RASD_LAB_HOST', `$env:COMPUTERNAME, 'Machine')")
    } elseif ($labHost -ne $computer) {
        $problems.Add("RASD_LAB_HOST is '$labHost' but this computer is '$computer' (the variable was copied from another machine, or the VM was renamed)")
    }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain) {
        $domain = ([string]$cs.Domain).Trim().ToLowerInvariant()
        $allowed = @((Get-RasdMachineVariable 'RASD_LAB_DOMAINS') -split ',' |
            ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
        foreach ($d in $allowed) {
            if (-not ($script:RasdLabSuffixes | Where-Object { $d.EndsWith($_) })) {
                $problems.Add("RASD_LAB_DOMAINS lists '$d', which does not end in a lab or reserved suffix ($($script:RasdLabSuffixes -join ' ')): only lab or reserved suffixes are accepted")
            }
        }
        if ($allowed -notcontains $domain) {
            $problems.Add("this computer is joined to the domain '$domain', which is not in the machine variable RASD_LAB_DOMAINS. If '$domain' is your lab domain, as administrator: [Environment]::SetEnvironmentVariable('RASD_LAB_DOMAINS', '$domain', 'Machine')")
        }
    }
    return $problems.ToArray()
}

function Assert-RasdLab {
    <# Throws, listing every reason, unless this host is a confirmed lab machine. #>
    param([switch] $DryRun)
    if ($DryRun) { return }
    $problems = @(Get-RasdLabProblems)
    if ($problems.Count) {
        throw ("Refusing to run: this host is not a confirmed RASD lab machine.`n  - " + ($problems -join "`n  - ") +
               "`nSee red/lab/README.md (Lab guard).")
    }
}
