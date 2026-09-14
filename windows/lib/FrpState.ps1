# FrpState.ps1 — directories, client-id, identity storage, client-state.json.

if ((Test-Path variable:script:FrpStateLoaded) -and $script:FrpStateLoaded) { return }
$script:FrpStateLoaded = $true

function Initialize-FrpDirectories {
    $dirs = @(
        (Get-FrpWindowsRoot),
        (Get-FrpBinDir),
        (Get-FrpConfigDir),
        (Get-FrpStateDir),
        (Get-FrpCertsDir),
        (Get-FrpLogsDir),
        (Get-FrpToolsDir),
        (Get-FrpLibDir),
        (Get-FrpBackupDir)
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
    # Backups hold copies of frpc.toml, which carries the plaintext FRP token,
    # so they are restricted exactly like config/state/certs.
    foreach ($sensitive in @((Get-FrpStateDir), (Get-FrpConfigDir), (Get-FrpCertsDir), (Get-FrpBackupDir))) {
        Restrict-FrpDirectoryAcl -Path $sensitive
    }
}

function Restrict-FrpDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($env:FRP_WINDOWS_FAIL_ACL -eq '1') {
        throw 'ERROR: simulated ACL failure (FRP_WINDOWS_FAIL_ACL=1)'
    }
    if (Test-FrpIsWindowsHost) {
        try {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($acl.Access)) {
                try { [void]$acl.RemoveAccessRule($rule) } catch { }
            }
            $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $prop = [System.Security.AccessControl.PropagationFlags]::None
            $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, $inherit, $prop, $type)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
        } catch {
            throw ("ERROR: failed to restrict directory ACL: {0}" -f $Path)
        }
        return
    }
    Set-FrpPosixMode -Path $Path -Mode '700'
}

function Set-FrpPosixMode {
    <#
    .SYNOPSIS
      Owner-only permissions for the non-Windows test host, where the Windows
      ACL model does not exist. Prefers the in-process API so the hot paths do
      not fork chmod on every state write.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('600', '700')][string]$Mode = '600'
    )
    $target = $(if ($Mode -eq '700') { 'UserRead,UserWrite,UserExecute' } else { 'UserRead,UserWrite' })
    try {
        $desired = [System.IO.UnixFileMode]$target
        if ([System.IO.File]::GetUnixFileMode($Path) -ne $desired) {
            [System.IO.File]::SetUnixFileMode($Path, $desired)
        }
        return
    } catch { }
    try {
        & chmod $Mode -- $Path 2>$null
    } catch { }
}

function New-FrpProtectedDirectory {
    <#
    .SYNOPSIS
      Create a directory and apply the product-enforced restrictive ACL
      (SYSTEM / Administrators only on Windows, 0700 on a test host).
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    Restrict-FrpDirectoryAcl -Path $Path
    return $Path
}

function Copy-FrpProtectedFile {
    <#
    .SYNOPSIS
      Copy a file that may carry the plaintext FRP token (frpc.toml) or other
      sensitive state, restricting the copy before returning.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Restrict-FrpFileAcl -Path $Destination
    return $Destination
}

function New-FrpBackupRoot {
    <#
    .SYNOPSIS
      Create a timestamped, ACL-restricted backup directory under backups\.
      Every caller snapshots frpc.toml, so the directory must never inherit
      permissive parent ACLs.
    #>
    param([Parameter(Mandatory = $true)][string]$Prefix)
    Initialize-FrpDirectories
    $null = New-FrpProtectedDirectory -Path (Get-FrpBackupDir)
    $name = '{0}-{1}-{2}' -f $Prefix, (Get-Date -Format 'yyyyMMddHHmmss'), [guid]::NewGuid().ToString('N').Substring(0, 8)
    return (New-FrpProtectedDirectory -Path (Join-Path (Get-FrpBackupDir) $name))
}

function Restrict-FrpFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($env:FRP_WINDOWS_FAIL_ACL -eq '1') {
        throw 'ERROR: simulated ACL failure (FRP_WINDOWS_FAIL_ACL=1)'
    }
    if (Test-FrpIsWindowsHost) {
        try {
            $acl = Get-Acl -LiteralPath $Path
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @($acl.Access)) {
                try { [void]$acl.RemoveAccessRule($rule) } catch { }
            }
            $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, $rights, $type)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
        } catch {
            throw ("ERROR: failed to restrict ACL on sensitive path: {0}" -f $Path)
        }
        return
    }
    Set-FrpPosixMode -Path $Path -Mode '600'
}

function Get-FrpExpectedHostId {
    <#
    .SYNOPSIS
      Build host_id matching Linux install-client / Access Control expected_host_id.
      Format: sanitize(hostname) + '-' + machine_id[0:8]
      sanitize: tr -cs 'A-Za-z0-9._-' '-'
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Hostname,
        [Parameter(Mandatory = $true)][string]$MachineId
    )
    $safe = [regex]::Replace([string]$Hostname, '[^A-Za-z0-9._-]+', '-')
    $mid = [string]$MachineId
    if ($mid.Length -gt 8) { $mid = $mid.Substring(0, 8) }
    return ('{0}-{1}' -f $safe, $mid)
}

function Test-FrpClientIdWellFormed {
    <#
    .SYNOPSIS
      Shape check for the immutable client id. New ids are 32 hex characters;
      the wider charset keeps ids written by older releases usable.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $v = ([string]$Value).Trim()
    if ($v.Length -lt 16) { return $false }
    return ($v -match '^[A-Za-z0-9._-]+$')
}

function Write-FrpClientIdFile {
    param([Parameter(Mandatory = $true)][string]$ClientId)
    $path = Get-FrpClientIdPath
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $ClientId + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
    return $path
}

function Get-FrpCommittedMachineId {
    <#
    .SYNOPSIS
      The machine id this host has already committed to, taken from
      client-state.json (authoritative) or, before the state file exists, from
      the crash-safe pending-enrollment record. Returns $null when this host
      has never committed one. Throws when a record exists but cannot be
      trusted: silently inventing a new id there would orphan the server-side
      reservations bound to the old one.
    #>
    $stateId = $null
    $statePath = Get-FrpStatePath
    if (Test-Path -LiteralPath $statePath) {
        $state = $null
        try {
            $state = Read-FrpClientState
        } catch {
            throw 'ERROR: client-state.json is present but unreadable, so this host''s machine id cannot be confirmed. Refusing to generate a new client identity. Restore client-state.json, or uninstall locally and re-enroll.'
        }
        $stateId = ([string]$state.machine_id).Trim()
        if (-not (Test-FrpClientIdWellFormed -Value $stateId)) {
            throw 'ERROR: client-state.json does not contain a usable machine_id. Refusing to generate a new client identity. Restore client-state.json, or uninstall locally and re-enroll.'
        }
    }
    $pendingId = $null
    $pending = Get-FrpPendingEnrollRaw
    if ($null -ne $pending) {
        $candidate = ([string]$pending.machine_id).Trim()
        if (Test-FrpClientIdWellFormed -Value $candidate) { $pendingId = $candidate }
    }
    if ($stateId -and $pendingId -and $stateId -ne $pendingId) {
        throw ("ERROR: local records disagree about this host's machine id (client-state.json '{0}' vs enroll-pending.json '{1}'). Refusing to guess. Uninstall locally and re-enroll." -f $stateId, $pendingId)
    }
    if ($stateId) { return $stateId }
    return $pendingId
}

function Get-FrpOrCreateClientId {
    <#
    .SYNOPSIS
      Return this host's immutable client id, creating one only on a genuinely
      fresh install. A missing, truncated, or corrupt client-id file is
      recovered from the committed machine id when that is available, and is
      otherwise a fail-closed error: a fresh random id would silently orphan
      the client's server-side identity and port reservations.
    #>
    Initialize-FrpDirectories
    $path = Get-FrpClientIdPath
    $filePresent = Test-Path -LiteralPath $path
    $fileId = $null
    if ($filePresent) {
        try {
            $fileId = ([System.IO.File]::ReadAllText($path)).Trim()
        } catch {
            throw 'ERROR: the client id file exists but could not be read. Refusing to generate a new client identity. Restore state\client-id, or uninstall locally and re-enroll.'
        }
    }

    $committedId = Get-FrpCommittedMachineId

    if (Test-FrpClientIdWellFormed -Value $fileId) {
        if ($committedId -and $committedId -ne $fileId) {
            throw ("ERROR: client identity mismatch: state\client-id is '{0}' but this host is enrolled as '{1}'. Refusing to generate a new client identity, which would orphan the server-side reservations. Restore the matching state\client-id, or uninstall locally and re-enroll." -f $fileId, $committedId)
        }
        return $fileId
    }

    if ($committedId) {
        if ($filePresent) {
            Write-Host 'WARNING: state\client-id is corrupt; recovering the exact enrolled machine id from local records.'
        } else {
            Write-Host 'WARNING: state\client-id is missing; recovering the exact enrolled machine id from local records.'
        }
        Write-FrpClientIdFile -ClientId $committedId | Out-Null
        return $committedId
    }

    if ($filePresent) {
        throw 'ERROR: state\client-id is corrupt and no enrolled machine id is recorded locally, so the original client identity cannot be recovered. Refusing to generate a new one. Uninstall locally and re-enroll.'
    }

    $id = New-FrpClientId
    Write-FrpClientIdFile -ClientId $id | Out-Null
    return $id
}

function Test-FrpIsEnrolled {
    $statePath = Get-FrpStatePath
    $tomlPath = Get-FrpTomlPath
    $pubPath = Get-FrpIdentityPubPath
    $keyPath = Get-FrpIdentityKeyPath
    if (-not (Test-Path -LiteralPath $statePath)) { return $false }
    if (-not (Test-Path -LiteralPath $tomlPath)) { return $false }
    if (-not (Test-Path -LiteralPath $pubPath)) { return $false }
    if (-not (Test-Path -LiteralPath $keyPath)) { return $false }
    return $true
}

function Assert-FrpLocalMachineDpapiAvailable {
    if ($env:FRP_WINDOWS_FAIL_DPAPI_LOCALMACHINE -eq '1') {
        throw 'ERROR: LocalMachine DPAPI is required for persistent Windows secrets'
    }
}

function Save-FrpIdentityKey {
    param([Parameter(Mandatory = $true)][string]$PrivatePem)
    Initialize-FrpDirectories
    $stateDir = Get-FrpStateDir
    if (Test-FrpIsWindowsHost) {
        Assert-FrpLocalMachineDpapiAvailable
        Add-Type -AssemblyName System.Security -ErrorAction Stop | Out-Null
        $path = Join-Path $stateDir 'client-identity.key.dpapi'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PrivatePem)
        $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)
        [System.IO.File]::WriteAllBytes($path, $protected)
        Restrict-FrpFileAcl -Path $path
        return $path
    }
    Write-Warning 'DPAPI unavailable; storing identity key as a plain file under the test root. Do not use this mode on production Windows hosts.'
    $path = Join-Path $stateDir 'client-identity.key'
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $PrivatePem)
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
    return $path
}

function Read-FrpIdentityKey {
    $stateDir = Get-FrpStateDir
    $dpapi = Join-Path $stateDir 'client-identity.key.dpapi'
    $plain = Join-Path $stateDir 'client-identity.key'
    if ((Test-Path -LiteralPath $dpapi) -and (Test-FrpIsWindowsHost)) {
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue | Out-Null
        $protected = [System.IO.File]::ReadAllBytes($dpapi)
        Assert-FrpLocalMachineDpapiAvailable
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    if (Test-Path -LiteralPath $plain) {
        return [System.IO.File]::ReadAllText($plain)
    }
    throw 'ERROR: management identity is missing'
}

function Save-FrpIdentityPublic {
    param([Parameter(Mandatory = $true)][string]$PublicPem)
    Initialize-FrpDirectories
    $path = Get-FrpIdentityPubPath
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $PublicPem)
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Save-FrpIdentityMac {
    param([Parameter(Mandatory = $true)][string]$MacKeyHex)
    Initialize-FrpDirectories
    $path = Get-FrpIdentityMacPath
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $MacKeyHex.Trim() + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
}

function Read-FrpIdentityMac {
    $path = Get-FrpIdentityMacPath
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'ERROR: management MAC key is missing'
    }
    return ([System.IO.File]::ReadAllText($path)).Trim()
}

function ConvertTo-FrpServiceMap {
    param($Services)
    $map = [ordered]@{}
    if ($null -eq $Services) { return $map }
    if ($Services -is [System.Collections.IDictionary]) {
        foreach ($k in $Services.Keys) {
            $item = $Services[$k]
            $rec = ConvertTo-FrpServiceRecord -Item $item -DefaultId ([string]$k)
            $map[$rec.id] = $rec
        }
        return $map
    }
    # ConvertFrom-Json object map: { rdp = {...}; ssh = {...} }
    # Empty JSON object {} becomes a PSCustomObject with no note properties.
    # Do NOT use this branch for arrays (they also expose .PSObject.Properties).
    if ($Services -is [System.Management.Automation.PSCustomObject]) {
        $props = @($Services.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })
        if ($props.Count -eq 0) {
            return $map
        }
        $first = $props[0].Value
        $looksLikeMap = $false
        if ($null -ne $first -and -not ($first -is [string]) -and -not ($first -is [ValueType])) {
            $looksLikeMap = $true
        }
        if ($looksLikeMap) {
            foreach ($p in $props) {
                $rec = ConvertTo-FrpServiceRecord -Item $p.Value -DefaultId ([string]$p.Name)
                $map[$rec.id] = $rec
            }
            return $map
        }
    }
    foreach ($item in @($Services)) {
        $rec = ConvertTo-FrpServiceRecord -Item $item -DefaultId $null
        $map[$rec.id] = $rec
    }
    return $map
}

function ConvertTo-FrpServiceRecord {
    param($Item, $DefaultId)
    $ht = @{}
    if ($Item -is [System.Collections.IDictionary]) {
        foreach ($k in $Item.Keys) { $ht[[string]$k] = $Item[$k] }
    } else {
        foreach ($p in $Item.PSObject.Properties) { $ht[$p.Name] = $p.Value }
    }
    $sid = [string]$ht['id']
    if (-not $sid) { $sid = [string]$DefaultId }
    if (-not $sid) { throw 'ERROR: service id is required' }
    $preset = [string]$ht['preset']
    if (-not $preset) { $preset = 'custom' }
    $preset = $preset.Trim().ToLowerInvariant()
    # Client-side convenience: rdp is a first-class TCP 3389 preset.
    if ($preset -eq 'rdp') {
        if (-not $ht['local_port']) { $ht['local_port'] = 3389 }
        if (-not $ht['local_ip']) { $ht['local_ip'] = '127.0.0.1' }
        if (-not $ht['name']) { $ht['name'] = 'RDP' }
    }
    $rec = [ordered]@{
        id         = $sid.ToLowerInvariant()
        name       = $(if ($ht['name']) { [string]$ht['name'] } else { $sid })
        preset     = $preset
        protocol   = 'tcp'
        local_ip   = $(if ($ht['local_ip']) { [string]$ht['local_ip'] } else { '127.0.0.1' })
        local_port = [int]$ht['local_port']
        enabled    = $(if ($null -eq $ht['enabled']) { $true } else { [bool]$ht['enabled'] })
    }
    if ($null -ne $ht['remote_port'] -and [string]$ht['remote_port'] -ne '') {
        $rec['remote_port'] = [int]$ht['remote_port']
    }
    if ($preset -eq 'ssh' -and $ht['ssh_user']) {
        $rec['ssh_user'] = [string]$ht['ssh_user']
    }
    if ($null -ne $ht['health_check'] -and $ht['health_check']) {
        $hc = $ht['health_check']
        $hcMap = @{}
        if ($hc -is [hashtable] -or $hc -is [System.Collections.IDictionary]) {
            foreach ($k in $hc.Keys) { $hcMap[[string]$k] = $hc[$k] }
        } else {
            foreach ($p in $hc.PSObject.Properties) { $hcMap[$p.Name] = $p.Value }
        }
        $hcType = ([string]$hcMap['type']).Trim().ToLowerInvariant()
        if ($hcType -eq 'tcp' -or $hcType -eq 'http') {
            $normalized = [ordered]@{
                type              = $hcType
                timeout_seconds   = $(if ($hcMap.ContainsKey('timeout_seconds')) { [int]$hcMap['timeout_seconds'] } else { 3 })
                interval_seconds  = $(if ($hcMap.ContainsKey('interval_seconds')) { [int]$hcMap['interval_seconds'] } else { 10 })
                max_failed        = $(if ($hcMap.ContainsKey('max_failed')) { [int]$hcMap['max_failed'] } else { 1 })
            }
            if ($hcType -eq 'http') {
                $normalized['path'] = $(if ($hcMap.ContainsKey('path') -and [string]$hcMap['path']) { [string]$hcMap['path'] } else { '/health' })
            }
            $rec['health_check'] = [pscustomobject]$normalized
        }
    }
    return $rec
}

function Get-FrpEnrollServiceList {
    <#
    .SYNOPSIS
      Build enrollment request service objects for the allocator wire protocol.
      Local UI alias "rdp" is mapped to preset=custom (server ALLOWED_PRESETS).
    #>
    param($Services)
    $list = New-Object System.Collections.ArrayList
    $map = ConvertTo-FrpServiceMap -Services $Services
    foreach ($sid in $map.Keys) {
        $item = $map[$sid]
        if ($item.enabled -eq $false) { continue }
        $preset = [string]$item.preset
        $wirePreset = $preset
        # RDP is a local UX alias; wire protocol uses custom TCP.
        if ($preset -eq 'rdp') { $wirePreset = 'custom' }
        $out = [ordered]@{
            id         = [string]$item.id
            name       = [string]$item.name
            protocol   = 'tcp'
            local_ip   = [string]$item.local_ip
            local_port = [int]$item.local_port
            preset     = $wirePreset
        }
        if ($wirePreset -eq 'ssh' -and $item.ssh_user) {
            $out['ssh_user'] = [string]$item.ssh_user
        }
        $hc = $null
        if ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
            if ($item.Contains('health_check')) { $hc = $item['health_check'] }
        } elseif ($null -ne $item.PSObject -and $null -ne $item.PSObject.Properties['health_check']) {
            $hc = $item.health_check
        }
        if ($null -ne $hc -and $hc) {
            $out['health_check'] = $hc
        }
        [void]$list.Add([pscustomobject]$out)
    }
    return ,$list.ToArray()
}

function Save-FrpClientState {
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$FrpServer,
        [Parameter(Mandatory = $true)][int]$FrpServerPort,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$HostId,
        [Parameter(Mandatory = $true)]$Services,
        [string]$Transport = 'tcp',
        [string]$ProjectVersion,
        [string]$FrpVersion,
        [string]$InstallStatus,
        [string]$PublicHostname
    )
    Initialize-FrpDirectories
    $transport = ([string]$Transport).Trim().ToLowerInvariant()
    if (-not $transport) { $transport = 'tcp' }
    if ($transport -ne 'tcp' -and $transport -ne 'wss') {
        throw 'ERROR: unsupported FRP transport'
    }
    $map = ConvertTo-FrpServiceMap -Services $Services
    # Ensure no secrets in state
    foreach ($sid in @($map.Keys)) {
        foreach ($bad in @('token', 'secret', 'enrollment_secret', 'private_key', 'token_ciphertext')) {
            if ($map[$sid].Contains($bad)) {
                throw 'ERROR: client-state.json must not contain secrets'
            }
        }
    }
    $enabledAny = $false
    foreach ($sid in $map.Keys) {
        if ($map[$sid].enabled -ne $false) { $enabledAny = $true; break }
    }
    $state = [ordered]@{
        schema_version   = 1
        allocator_url    = $AllocatorUrl
        frp_server       = $FrpServer
        frp_server_port  = [int]$FrpServerPort
        frp_transport    = $transport
        hostname         = $Hostname
        machine_id       = $MachineId
        host_id          = $HostId
        services         = $map
        management_only  = (-not $enabledAny)
        project_version  = $(if ($ProjectVersion) { $ProjectVersion } else { Get-FrpProjectVersion })
        frp_version      = $(if ($FrpVersion) { $FrpVersion } else { Get-FrpUpstreamVersion })
        platform         = 'windows'
        install_status   = $(if ($InstallStatus) { $InstallStatus } elseif (-not $enabledAny) { 'management_only' } else { 'installed' })
    }
    $hostnamePresent = $PSBoundParameters.ContainsKey('PublicHostname')
    if ($hostnamePresent) {
        $alias = ([string]$PublicHostname).Trim()
        if ($alias) { $state['public_hostname'] = $alias }
    } else {
        $pathExisting = Get-FrpStatePath
        if (Test-Path -LiteralPath $pathExisting) {
            try {
                $prev = Read-FrpClientState
                if (@($prev.PSObject.Properties.Name) -contains 'public_hostname') {
                    $prevAlias = ([string]$prev.public_hostname).Trim()
                    if ($prevAlias) { $state['public_hostname'] = $prevAlias }
                }
            } catch { }
        }
    }
    $path = Get-FrpStatePath
    $json = Get-FrpCanonicalJson -Object $state
    # Pretty-print for operators (canonical used only for crypto). Use ConvertTo-Json carefully.
    $pretty = ($state | ConvertTo-Json -Depth 8)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $pretty + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
    return $path
}

function Read-FrpClientState {
    $path = Get-FrpStatePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'ERROR: client-state.json is missing'
    }
    $raw = [System.IO.File]::ReadAllText($path)
    return ($raw | ConvertFrom-Json)
}

function Test-FrpObjectHasProperty {
    param($Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        return $Object.Contains($Name)
    }
    return (@($Object.PSObject.Properties.Name) -contains $Name)
}

function Get-FrpStateChangeClass {
    <#
    .SYNOPSIS
      Classify draft vs current: local (name/ssh_user), runtime (ports/enable/add/remove), or none.
    #>
    param($Current, $Draft)
    $curMap = ConvertTo-FrpServiceMap -Services $Current.services
    $newMap = ConvertTo-FrpServiceMap -Services $Draft.services
    $hasRuntime = $false
    $hasLocal = $false
    $all = @{}
    foreach ($k in @($curMap.Keys)) { $all[[string]$k] = $true }
    foreach ($k in @($newMap.Keys)) { $all[[string]$k] = $true }
    foreach ($sid in @($all.Keys)) {
        $a = $null
        $b = $null
        if ($curMap.Contains($sid)) { $a = $curMap[$sid] }
        if ($newMap.Contains($sid)) { $b = $newMap[$sid] }
        if ($null -eq $a -or $null -eq $b) {
            $hasRuntime = $true
            continue
        }
        $aEn = ($a.enabled -ne $false)
        $bEn = ($b.enabled -ne $false)
        if ($aEn -ne $bEn) { $hasRuntime = $true }
        $aPort = 0
        $bPort = 0
        try { $aPort = [int]$a.local_port } catch { }
        try { $bPort = [int]$b.local_port } catch { }
        if ([string]$a.local_ip -ne [string]$b.local_ip -or $aPort -ne $bPort) {
            $hasRuntime = $true
        }
        if ([string]$a.name -ne [string]$b.name) { $hasLocal = $true }
        if ([string]$a.ssh_user -ne [string]$b.ssh_user) { $hasLocal = $true }
    }
    if ($hasRuntime) { return 'runtime' }
    if ($hasLocal) { return 'local' }
    return 'none'
}

function Get-FrpInstallStatus {
    if (-not (Test-Path -LiteralPath (Get-FrpStatePath))) { return $null }
    try {
        $state = Read-FrpClientState
        return [string]$state.install_status
    } catch {
        return $null
    }
}

function Set-FrpInstallStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('enrolling', 'enrolled_incomplete', 'installed', 'management_only')]
        [string]$Status
    )
    $path = Get-FrpStatePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw 'ERROR: client-state.json is missing; cannot set install_status'
    }
    $state = Read-FrpClientState
    $ht = ConvertTo-FrpPlainObject $state
    $ht['install_status'] = $Status
    if ($Status -eq 'management_only') {
        $ht['management_only'] = $true
    }
    $pretty = ($ht | ConvertTo-Json -Depth 8)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $pretty + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
}

function Test-FrpIsInstallComplete {
    $status = Get-FrpInstallStatus
    return ($status -eq 'installed' -or $status -eq 'management_only')
}

function Test-FrpCanResumeInstall {
    if (-not (Test-FrpIsEnrolled)) { return $false }
    $status = Get-FrpInstallStatus
    return ($status -eq 'enrolled_incomplete')
}

function Get-FrpIdentityPublicFingerprint {
    <#
    .SYNOPSIS
      SHA-256 fingerprint (hex) of this client's management public key PEM,
      when a local identity exists. Used only for crash-safe pending-enrollment
      recovery bookkeeping (Finding A; see Save-FrpPendingEnroll below), never
      for trust decisions, which remain signature-based.
    #>
    $path = Get-FrpIdentityPubPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $pem = [System.IO.File]::ReadAllText($path)
        return Get-FrpSha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($pem))
    } catch {
        return $null
    }
}

function Get-FrpPendingEnrollRaw {
    <#
    .SYNOPSIS
      Raw (undecrypted-secret) pending-enrollment record, or $null if absent
      or unreadable. Internal helper for Save-/Read-/Test-FrpPendingEnroll*.
    #>
    $path = Get-FrpPendingEnrollPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($path)
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Test-FrpPendingEnrollExists {
    Test-Path -LiteralPath (Get-FrpPendingEnrollPath)
}

function Test-FrpPendingEnrollMatches {
    <#
    .SYNOPSIS
      True when a crash-safe pending-enrollment transaction exists for this
      host's machine id. Callers must not treat a non-matching (e.g. stale,
      foreign) pending file as resumable.
    #>
    param([Parameter(Mandatory = $true)][string]$MachineId)
    $raw = Get-FrpPendingEnrollRaw
    if ($null -eq $raw) { return $false }
    return ([string]$raw.machine_id -eq $MachineId)
}

function Save-FrpPendingEnroll {
    <#
    .SYNOPSIS
      Finding A: Zero-Touch lost-response recovery. Persists the minimum
      needed to resume an interrupted zero-touch enrollment without
      re-redeeming a single-use Bootstrap Ticket: enrollment id/secret,
      machine id, a services snapshot/digest, the management key
      fingerprint, and (once the allocator has responded) the exact enroll
      response needed to finish the local commit without another network
      round trip.

      Stored under the Windows state directory (ProgramData\drlink\
      state\enroll-pending.json by default), restricted ACL (SYSTEM /
      Administrators only), atomic replace (temp file + Move-Item). The
      enrollment secret is DPAPI-protected with LocalMachine scope on a real
      Windows host (fail closed if LocalMachine DPAPI is unavailable). On a
      non-Windows / test host it is stored as plain JSON, matching
      Save-FrpIdentityKey test-root behavior.

      Never weakens ticket single-use semantics: this file never contains
      the Bootstrap Ticket itself, only the Enrollment ID/Secret pair the
      allocator already issued in exchange for it.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet('redeemed', 'enrolled')][string]$Phase,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$EnrollmentId,
        [Parameter(Mandatory = $true)][string]$EnrollmentSecret,
        [Parameter(Mandatory = $true)]$Services,
        [hashtable]$EnrollMeta,
        $AllocatedServices
    )
    Initialize-FrpDirectories
    $path = Get-FrpPendingEnrollPath
    $existing = Get-FrpPendingEnrollRaw

    $now = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $createdAt = $now
    if ($existing -and $existing.created_at) { $createdAt = $existing.created_at }

    $servicesPlain = ConvertTo-FrpPlainObject $Services
    $canonicalServices = Get-FrpCanonicalJson -Object $servicesPlain
    $digest = Get-FrpSha256Hex -Bytes ([System.Text.Encoding]::UTF8.GetBytes($canonicalServices))

    $record = [ordered]@{
        schema_version  = 1
        created_at      = $createdAt
        updated_at      = $now
        phase           = $Phase
        machine_id      = $MachineId
        hostname        = $Hostname
        allocator_url   = $AllocatorUrl
        enroll_id       = $EnrollmentId
        services        = $servicesPlain
        services_digest = $digest
    }
    $fp = Get-FrpIdentityPublicFingerprint
    if ($fp) { $record['mgmt_fingerprint'] = $fp }

    if (Test-FrpIsWindowsHost) {
        Assert-FrpLocalMachineDpapiAvailable
        Add-Type -AssemblyName System.Security -ErrorAction Stop | Out-Null
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($EnrollmentSecret)
        $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)
        $record['enroll_secret_dpapi'] = [Convert]::ToBase64String($protected)
    } else {
        Write-Warning 'DPAPI unavailable; storing pending-enrollment secret as plain JSON under the test root. Do not use this mode on production Windows hosts.'
        $record['enroll_secret'] = $EnrollmentSecret
    }

    if ($EnrollMeta) {
        $record['enroll_meta'] = ConvertTo-FrpPlainObject $EnrollMeta
    } elseif ($existing -and $existing.enroll_meta) {
        $record['enroll_meta'] = ConvertTo-FrpPlainObject $existing.enroll_meta
    }
    if ($AllocatedServices) {
        $record['allocated_services'] = ConvertTo-FrpPlainObject $AllocatedServices
    } elseif ($existing -and $existing.allocated_services) {
        $record['allocated_services'] = ConvertTo-FrpPlainObject $existing.allocated_services
    }

    $json = ($record | ConvertTo-Json -Depth 10)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
    return $path
}

function Read-FrpPendingEnroll {
    <#
    .SYNOPSIS
      Reads back the pending-enrollment record written by
      Save-FrpPendingEnroll, decrypting the DPAPI-protected secret when
      present. Returns $null if no pending record exists.
    #>
    $raw = Get-FrpPendingEnrollRaw
    if ($null -eq $raw) { return $null }
    $propNames = @($raw.PSObject.Properties.Name)
    $secret = $null
    if (($propNames -contains 'enroll_secret_dpapi') -and $raw.enroll_secret_dpapi) {
        $protected = [Convert]::FromBase64String([string]$raw.enroll_secret_dpapi)
        Assert-FrpLocalMachineDpapiAvailable
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $secret = [System.Text.Encoding]::UTF8.GetString($bytes)
    } elseif ($propNames -contains 'enroll_secret') {
        $secret = [string]$raw.enroll_secret
    }
    return @{
        Phase             = [string]$raw.phase
        MachineId         = [string]$raw.machine_id
        Hostname          = [string]$raw.hostname
        AllocatorUrl      = [string]$raw.allocator_url
        EnrollmentId      = [string]$raw.enroll_id
        EnrollmentSecret  = $secret
        Services          = @($raw.services)
        EnrollMeta        = $raw.enroll_meta
        AllocatedServices = @($raw.allocated_services)
        MgmtFingerprint   = [string]$raw.mgmt_fingerprint
    }
}

function Clear-FrpPendingEnroll {
    <#
    .SYNOPSIS
      Removes the pending-enrollment recovery transaction. Callers must only
      do this after the local commit (client-state.json + frpc.toml +
      management identity) has succeeded, so it is never replayed against a
      future, unrelated Enrollment Code.
    #>
    $path = Get-FrpPendingEnrollPath
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Get-FrpEnabledServiceCount {
    param($Services)
    if ($null -eq $Services) { return 0 }
    $map = ConvertTo-FrpServiceMap -Services $Services
    $n = 0
    foreach ($sid in $map.Keys) {
        if ($map[$sid].enabled -ne $false) { $n++ }
    }
    return $n
}

function Merge-FrpAllocatedPorts {
    param($LocalServices, $AllocatedList)
    $map = ConvertTo-FrpServiceMap -Services $LocalServices
    foreach ($a in @($AllocatedList)) {
        $sid = [string]$a.id
        if (-not $map.Contains($sid)) { continue }
        $map[$sid]['remote_port'] = [int]$a.remote_port
    }
    return $map
}
