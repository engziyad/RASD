<#
.SYNOPSIS
    RASD-Deceive · plant the decoys of deceive/decoys.yml in the lab, or remove them.
.DESCRIPTION
    Creates what the deception detections read, exactly as the inventory describes it:

      -Accounts   the honey accounts and the honey SPN account in the lab domain (needs the
                  ActiveDirectory module and a lab domain admin): svc_backup_adm with the lure in its
                  description, adm_helpdesk_tier2 with Kerberos pre-authentication disabled,
                  svc_sqlreport with its service principal name and RC4-only encryption so that
                  opsec-aware roasting tools still select it. Every decoy gets a random 40-character
                  password that is written nowhere - the "password" in the lures is a plausible wrong
                  one - and belongs to no group, so a decoy credential never grants access: every
                  attempt to use one fails, and every attempt is the alert.
      -Files      the three honey files under -DecoyRoot (C:\Shares by default): a real spreadsheet
                  of decoy service accounts, a password-manager database that carries the KDBX
                  signature and random content, and an onboarding note; each with an audit entry that
                  makes Windows write 4663 for every data access by Everyone, and the File System
                  audit subcategory enabled (needs an elevated session).
      -Shares     the IT and Public SMB shares over the decoy root, so the files are reached as the
                  inventory names them (needs an elevated session).
      -Remove     deletes the decoys this script created (accounts and files), for a lab reset.

    The decoy host (OpenCanary) is configured from deceive/opencanary/settings.json on its own VM.
    Nothing here runs outside a machine its owner marked as a RASD lab (red/lab/README.md, Lab guard);
    for a production deployment, take the identities from the inventory through your change process -
    the script is the specification, not the tool.
.EXAMPLE
    .\Deploy-RasdDecoys.ps1 -LabConfirmed -Accounts -Files -Shares
    .\Deploy-RasdDecoys.ps1 -LabConfirmed -Files -DecoyRoot D:\Shares -WhatIf
    .\Deploy-RasdDecoys.ps1 -LabConfirmed -Remove -Accounts -Files
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [switch] $LabConfirmed,
    [switch] $Accounts,
    [switch] $Files,
    [switch] $Shares,
    [switch] $Remove,
    [string] $DecoyRoot = 'C:\Shares'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $LabConfirmed) { throw 'Refusing to run without -LabConfirmed.' }
. (Join-Path $PSScriptRoot '..\red\lab\RasdLabGuard.ps1')
Assert-RasdLab
if (-not ($Accounts -or $Files -or $Shares)) { throw 'Choose what to deploy: -Accounts, -Files and/or -Shares (add -Remove to take them away).' }

# ---------------------------------------------------------------- the inventory, as the rules read it
# deceive/decoys.yml is the source; rasd deceive --rename rewrites these literals with it.
$HoneyAccounts = @(
    [pscustomobject]@{ Name = 'svc_backup_adm';     Description = 'Backup service account - pw reset 2024-03, temp pw in \\LAB-FS01\IT\Passwords\service_accounts.xlsx'; PreAuth = $true;  Spn = $null }
    [pscustomobject]@{ Name = 'adm_helpdesk_tier2'; Description = 'Helpdesk tier 2 - legacy admin, do not remove (ticket 48112)';                                          PreAuth = $false; Spn = $null }
    [pscustomobject]@{ Name = 'svc_sqlreport';      Description = 'SQL Server Reporting (SQLRPT01) service account';                                                      PreAuth = $true;  Spn = 'MSSQLSvc/sqlrpt01.lab.local:1433' }
)
$HoneyFiles = @(
    [pscustomobject]@{ Path = '\IT\Passwords\service_accounts.xlsx';     Kind = 'xlsx' }
    [pscustomobject]@{ Path = '\IT\Tools\credentials_backup.kdbx';       Kind = 'kdbx' }
    [pscustomobject]@{ Path = '\Public\Onboarding\vpn_and_wifi_codes.txt'; Kind = 'txt' }
)
$DecoyShares = @(
    [pscustomobject]@{ Name = 'IT';     Folder = 'IT' }
    [pscustomobject]@{ Name = 'Public'; Folder = 'Public' }
)
$DecoyPortal = 'http://nas01.lab.local'       # the decoy host of the inventory (lab-canary-01)

function New-RandomPassword {
    $bytes = New-Object byte[] 30
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ConvertTo-SecureString -String ([Convert]::ToBase64String($bytes)) -AsPlainText -Force   # 40 characters, kept nowhere
}

function Test-Elevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- accounts
function Deploy-Accounts {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain
    foreach ($a in $HoneyAccounts) {
        $existing = Get-ADUser -Filter "sAMAccountName -eq '$($a.Name)'" -Properties Description -ErrorAction SilentlyContinue
        if ($Remove) {
            if ($existing) {
                if ($existing.Description -ne $a.Description) { Write-Warning "$($a.Name) does not carry the decoy's description; not removing an account that may be real"; continue }
                if ($PSCmdlet.ShouldProcess($a.Name, 'remove decoy account')) { Remove-ADUser -Identity $existing -Confirm:$false; Write-Host "removed $($a.Name)" }
            } else { Write-Host "$($a.Name) is not present" }
            continue
        }
        if ($existing) {
            if ($existing.Description -ne $a.Description) { throw "$($a.Name) already exists without the decoy's description; refusing to turn an account that may be real into a decoy" }
            Write-Host "$($a.Name) already deployed"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($a.Name, 'create decoy account')) { continue }
        $params = @{
            Name = $a.Name; SamAccountName = $a.Name; UserPrincipalName = "$($a.Name)@$($domain.DNSRoot)"
            Description = $a.Description; AccountPassword = (New-RandomPassword); Enabled = $true
            PasswordNeverExpires = $true; CannotChangePassword = $true
        }
        if ($a.Spn) { $params['ServicePrincipalNames'] = @($a.Spn) }
        New-ADUser @params
        if (-not $a.PreAuth) {
            # the AS-REP roasting lure: a TGT without pre-authentication (4768, PreAuthType 0). The password
            # is 40 random characters, so the roasted hash is worth nothing
            Set-ADAccountControl -Identity $a.Name -DoesNotRequirePreAuth $true
        }
        if ($a.Spn) {
            # RC4 only (msDS-SupportedEncryptionTypes 4): tools that skip AES-enabled accounts to avoid the RC4
            # downgrade signature still select the decoy
            Set-ADUser -Identity $a.Name -Replace @{ 'msDS-SupportedEncryptionTypes' = 4 }
        }
        $detail = if ($a.Spn) { " with SPN $($a.Spn), RC4 only" } elseif (-not $a.PreAuth) { ' with pre-authentication disabled' } else { ' with the lure in its description' }
        Write-Host "created $($a.Name)$detail"
    }
    if (-not $Remove) {
        Write-Host 'the honey SPN host must resolve: add sqlrpt01 (and nas01) to the lab DNS, pointing at the decoy host (10.0.0.40)' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------- files
function New-MinimalXlsx([string] $Path, [string[][]] $Rows) {
    # A real OOXML spreadsheet (inline strings) that Excel opens, without Excel: one sheet, one table.
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $esc = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
    $sheetRows = for ($r = 0; $r -lt $Rows.Count; $r++) {
        $cells = for ($c = 0; $c -lt $Rows[$r].Count; $c++) {
            $ref = [char](65 + $c) + [string]($r + 1)
            "<c r=`"$ref`" t=`"inlineStr`"><is><t>$(& $esc $Rows[$r][$c])</t></is></c>"
        }
        "<row r=`"$($r + 1)`">$($cells -join '')</row>"
    }
    $parts = [ordered]@{
        '[Content_Types].xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
        '_rels/.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        'xl/workbook.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Service accounts" sheetId="1" r:id="rId1"/></sheets></workbook>'
        'xl/_rels/workbook.xml.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
        'xl/worksheets/sheet1.xml' = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><worksheet xmlns=`"http://schemas.openxmlformats.org/spreadsheetml/2006/main`"><sheetData>$($sheetRows -join '')</sheetData></worksheet>"
    }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($name in $parts.Keys) {
                $entry = $zip.CreateEntry($name)
                $writer = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
                try { $writer.Write($parts[$name]) } finally { $writer.Dispose() }
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}

function New-DecoyKdbx([string] $Path) {
    # The KDBX 4 signature (0x9AA2D903, 0xB54BFB67), then random bytes: a database no password opens,
    # which is the point - it only needs to be worth taking, and taking it is a read.
    $bytes = New-Object byte[] 24576
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $sig = [byte[]](0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0x00, 0x00, 0x04, 0x00)
    [Array]::Copy($sig, 0, $bytes, 0, $sig.Length)
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Set-DecoyAudit([string] $Path) {
    # Everyone, success, the data accesses the rule reads: ReadData, WriteData, AppendData, Delete.
    $acl = Get-Acl -LiteralPath $Path -Audit
    $rights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
              [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::Delete
    $rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone', $rights, [System.Security.AccessControl.AuditFlags]::Success)
    $acl.SetAuditRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Deploy-Files {
    foreach ($f in $HoneyFiles) {
        $path = Join-Path $DecoyRoot $f.Path.TrimStart('\')
        if ($Remove) {
            if (Test-Path -LiteralPath $path) { if ($PSCmdlet.ShouldProcess($path, 'remove decoy file')) { Remove-Item -LiteralPath $path -Force; Write-Host "removed $path" } }
            else { Write-Host "$path is not present" }
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($path, 'create decoy file with audit entry')) { continue }
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        switch ($f.Kind) {
            'xlsx' {
                # the lure: plausible accounts with plausible WRONG passwords; the decoys' real passwords are random and kept nowhere
                New-MinimalXlsx -Path $path -Rows @(
                    @('Account', 'Purpose', 'Password', 'Owner', 'Notes'),
                    @('svc_backup_adm', 'Backup agent (all file servers)', 'Backup#2024!', 'IT Ops', 'reset 2024-03, rotate when the new vault is ready'),
                    @('svc_sqlreport', 'SQL Server Reporting - SQLRPT01', 'Rep0rting@sql', 'DBA', 'runs the nightly report jobs'),
                    @('adm_helpdesk_tier2', 'Helpdesk tier 2 admin (legacy)', 'Helpdesk2019$', 'Service desk', 'do not remove - ticket 48112'),
                    @('nas01 admin', "NAS portal $DecoyPortal", 'nas-admin-01', 'IT Ops', 'local account on the NAS')
                )
            }
            'kdbx' { New-DecoyKdbx -Path $path }
            'txt' {
                $text = @(
                    'Onboarding - network access (keep this file in the Public share for new joiners)',
                    '',
                    "Wi-Fi (staff):  LAB-Staff / W1fi-Staff-2024",
                    "Wi-Fi (guest):  LAB-Guest / welcome-guest",
                    "VPN:            https://vpn.lab.local  - use your domain account; the helpdesk admin account adm_helpdesk_tier2 is for emergencies (ask IT Ops for the password)",
                    "NAS:            $DecoyPortal  - shared folders and backups (login: nas01 admin, see IT Ops)",
                    ''
                ) -join "`r`n"
                [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
            }
        }
        Set-DecoyAudit -Path $path
        # a file that was never touched looks planted: give the decoys an ordinary history
        $when = (Get-Date).AddDays(-(Get-Random -Minimum 40 -Maximum 400))
        (Get-Item -LiteralPath $path).CreationTime = $when
        (Get-Item -LiteralPath $path).LastWriteTime = $when.AddDays((Get-Random -Minimum 1 -Maximum 30))
        Write-Host "created $path with its audit entry"
    }
    if (-not $Remove) {
        if (Test-Elevated) {
            if ($PSCmdlet.ShouldProcess('File System audit subcategory', 'enable success auditing')) {
                & auditpol.exe /set /subcategory:'File System' /success:enable | Out-Null
                Write-Host 'audit policy: File System = Success'
            }
        } else {
            Write-Warning 'not elevated: enable the audit policy yourself (auditpol /set /subcategory:"File System" /success:enable), or 4663 is never written'
        }
    }
}

# ---------------------------------------------------------------- shares
function Deploy-Shares {
    if (-not (Test-Elevated)) { throw 'creating or removing SMB shares needs an elevated session' }
    foreach ($s in $DecoyShares) {
        $folder = Join-Path $DecoyRoot $s.Folder
        $existing = Get-SmbShare -Name $s.Name -ErrorAction SilentlyContinue
        if ($Remove) {
            if ($existing) { if ($PSCmdlet.ShouldProcess($s.Name, 'remove share')) { Remove-SmbShare -Name $s.Name -Force; Write-Host "removed share $($s.Name)" } }
            continue
        }
        if ($existing) { Write-Host "share $($s.Name) already exists ($($existing.Path))"; continue }
        if (-not $PSCmdlet.ShouldProcess($s.Name, "share $folder")) { continue }
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        New-SmbShare -Name $s.Name -Path $folder -ReadAccess 'Authenticated Users' -FullAccess 'Administrators' | Out-Null
        Write-Host "shared $folder as \\$env:COMPUTERNAME\$($s.Name)"
    }
}

if ($Accounts) { Deploy-Accounts }
if ($Files)    { Deploy-Files }
if ($Shares)   { Deploy-Shares }
if (-not $Remove) { Write-Host "done. Check the decoys any time with: .\Test-RasdDecoys.ps1 -DecoyRoot '$DecoyRoot'" }
