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
    if (Test-FrpIsWindowsHost) {
        Restrict-FrpDirectoryAcl -Path (Get-FrpStateDir)
        Restrict-FrpDirectoryAcl -Path (Get-FrpConfigDir)
        Restrict-FrpDirectoryAcl -Path (Get-FrpCertsDir)
    }
}

function Restrict-FrpDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-FrpIsWindowsHost)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($env:FRP_WINDOWS_FAIL_ACL -eq '1') {
        throw 'ERROR: simulated ACL failure (FRP_WINDOWS_FAIL_ACL=1)'
    }
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
    # Linux / test host: chmod 600 best-effort
    try {
        & chmod 600 -- $Path 2>$null
    } catch { }
}

function Get-FrpOrCreateClientId {
    Initialize-FrpDirectories
    $path = Get-FrpClientIdPath
    if (Test-Path -LiteralPath $path) {
        $id = ([System.IO.File]::ReadAllText($path)).Trim()
        if ($id.Length -ge 16) { return $id }
    }
    $id = New-FrpClientId
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $id + "`n")
    Restrict-FrpFileAcl -Path $tmp
    Move-Item -LiteralPath $tmp -Destination $path -Force
    Restrict-FrpFileAcl -Path $path
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

function Save-FrpIdentityKey {
    param([Parameter(Mandatory = $true)][string]$PrivatePem)
    Initialize-FrpDirectories
    $stateDir = Get-FrpStateDir
    if (Test-FrpIsWindowsHost) {
        $path = Join-Path $stateDir 'client-identity.key.dpapi'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($PrivatePem)
        $scope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        try {
            $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)
        } catch {
            # Fall back to CurrentUser if LocalMachine DPAPI is unavailable.
            $protected = [System.Security.Cryptography.ProtectedData]::Protect(
                $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
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
        try {
            $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $protected, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        } catch {
            $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }
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
    if ($Services -is [System.Management.Automation.PSCustomObject] -or ($Services.PSObject -and $Services.PSObject.Properties)) {
        $props = @($Services.PSObject.Properties | Where-Object { $_.MemberType -match 'NoteProperty|Property' })
        $looksLikeMap = $false
        if ($props.Count -gt 0) {
            $first = $props[0].Value
            if ($null -ne $first -and -not ($first -is [string]) -and -not ($first -is [ValueType])) {
                $looksLikeMap = $true
            }
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
        [string]$InstallStatus
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
