# FrpBootstrap.ps1 — zero-touch redeem → enroll → decrypt → config → download → start.

if ((Test-Path variable:script:FrpBootstrapLoaded) -and $script:FrpBootstrapLoaded) { return }
$script:FrpBootstrapLoaded = $true

# When this file lives in windows/lib, package root is windows/
if (-not $script:FrpWindowsSrcRoot) {
    if ($PSScriptRoot) {
        $script:FrpWindowsSrcRoot = Split-Path -Parent $PSScriptRoot
    }
}

function Clear-FrpSecretEnv {
    foreach ($name in @(
            'FRP_BOOTSTRAP_TICKET', 'FRP_ENROLL_SECRET', 'FRP_ENROLLMENT_SECRET',
            'FRP_TOKEN', 'FRP_SERVER_TOKEN', 'MGMT_ENROLL_SECRET'
        )) {
        if (Test-Path "Env:$name") {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        }
    }
}

function Expand-FrpZipSafe {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$DestinationDir,
        [Parameter(Mandatory = $true)][string]$EntryName
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $target = $null
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName -replace '\\', '/'
            if ($name.EndsWith('/')) { continue }
            $leaf = Split-Path -Leaf $name
            if ($leaf -ieq $EntryName) {
                # Zip-slip: reject absolute / parent traversal
                if ($name.Contains('..') -or $name.StartsWith('/') -or $name -match '^[A-Za-z]:') {
                    throw 'ERROR: unsafe zip entry rejected'
                }
                $target = $entry
                break
            }
        }
        if (-not $target) {
            throw ("ERROR: {0} not found in FRP archive" -f $EntryName)
        }
        if (-not (Test-Path -LiteralPath $DestinationDir)) {
            New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $outPath = Join-Path $DestinationDir $EntryName
        $tmp = "$outPath.tmp"
        $fs = [System.IO.File]::Create($tmp)
        try {
            $es = $target.Open()
            try { $es.CopyTo($fs) } finally { $es.Dispose() }
        } finally { $fs.Dispose() }
        Move-Item -LiteralPath $tmp -Destination $outPath -Force
        return $outPath
    } finally {
        $zip.Dispose()
    }
}

function Install-FrpWindowsBinary {
    param(
        [string]$DownloadUrl,
        [string]$ExpectedSha256
    )
    Initialize-FrpDirectories
    if (-not $DownloadUrl) { $DownloadUrl = Get-FrpWindowsAmd64Url }
    if (-not $ExpectedSha256) { $ExpectedSha256 = Get-FrpWindowsAmd64Sha256 }
    $expected = $ExpectedSha256.Trim().ToLowerInvariant()
    if ($DownloadUrl -notmatch '^https://') {
        throw 'ERROR: FRP download URL must be https://'
    }

    $binDir = Get-FrpBinDir
    $dest = Get-FrpFrpcPath
    if ((Test-Path -LiteralPath $dest) -and $env:FRP_WINDOWS_SKIP_DOWNLOAD -eq '1') {
        return $dest
    }

    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) ("frp-win-" + [guid]::NewGuid().ToString('N') + '.zip')
    try {
        Write-Host 'Downloading FRP Windows amd64 package...'
        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
            $p = Start-Process -FilePath 'curl.exe' -ArgumentList @(
                '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                '-o', $tmpZip, $DownloadUrl
            ) -Wait -PassThru -NoNewWindow
            if ($p.ExitCode -ne 0) { throw 'ERROR: FRP download failed' }
        } else {
            # PS 5.1 / 7 compatible
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $wc = New-Object System.Net.WebClient
            try { $wc.DownloadFile($DownloadUrl, $tmpZip) } finally { $wc.Dispose() }
        }
        $actual = Get-FrpSha256HexOfFile -Path $tmpZip
        if ($actual -ne $expected) {
            throw 'ERROR: FRP package SHA256 mismatch'
        }
        Expand-FrpZipSafe -ZipPath $tmpZip -DestinationDir $binDir -EntryName 'frpc.exe' | Out-Null
        if (-not (Test-Path -LiteralPath $dest)) {
            throw 'ERROR: frpc.exe extract failed'
        }
        $verPath = Get-FrpVersionPath
        $verText = @(
            "PROJECT_VERSION=$(Get-FrpProjectVersion)"
            "FRP_VERSION=$(Get-FrpUpstreamVersion)"
            "FRP_SHA256_WINDOWS_AMD64=$expected"
        ) -join "`n"
        [System.IO.File]::WriteAllText($verPath, $verText + "`n")
        return $dest
    } finally {
        Remove-Item -LiteralPath $tmpZip -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-FrpBootstrapRedeem {
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$Ticket,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$Hostname
    )
    $origin = Get-FrpAllocatorOrigin -AllocatorUrl $AllocatorUrl
    $url = "$origin/bootstrap/redeem"
    $payload = [ordered]@{
        ticket     = $Ticket
        machine_id = $MachineId
        hostname   = $Hostname
    }
    # Compact JSON (no spaces) matching Linux client
    $body = Get-FrpCanonicalJson -Object $payload
    $respText = Invoke-FrpHttpsJson -Method POST -Url $url -Body $body
    $data = $respText | ConvertFrom-Json
    if ($data.error) {
        $cls = [string]$data.error_class
        if (-not $cls) { $cls = 'BOOTSTRAP_REDEEM_FAILED' }
        throw ("ERROR: {0} [{1}]" -f [string]$data.error, $cls)
    }
    $code = [string]$data.enrollment_code
    if (-not $code -or -not $code.Contains('.')) {
        throw 'ERROR: bootstrap response is missing enrollment data'
    }
    $parts = $code.Split('.', 2)
    $services = @($data.services)
    if ($services.Count -lt 0) {
        throw 'ERROR: bootstrap response is missing services'
    }
    return @{
        EnrollmentId     = $parts[0]
        EnrollmentSecret = $parts[1]
        Services         = $services
    }
}

function Invoke-FrpEnroll {
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$EnrollmentId,
        [Parameter(Mandatory = $true)][string]$EnrollmentSecret,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)]$Services,
        [string]$PublicPem
    )
    $enrollServices = Get-FrpEnrollServiceList -Services $Services
    $payload = [ordered]@{
        machine_id = $MachineId
        hostname   = $Hostname
        services   = @($enrollServices)
    }
    if ($PublicPem) {
        $payload['mgmt_pubkey'] = $PublicPem
        $payload['mgmt_alg'] = 'ecdsa-p256-sha256'
    }
    $body = Get-FrpCanonicalJson -Object $payload
    $ts = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $sig = Get-FrpEnrollmentSignature -Secret $EnrollmentSecret -Timestamp ([string]$ts) -Body $body
    $headers = @{
        'X-Enrollment-ID' = $EnrollmentId
        'X-Timestamp'     = [string]$ts
        'X-Signature'     = $sig
    }
    $respText = Invoke-FrpHttpsJson -Method POST -Url $AllocatorUrl -Body $body -Headers $headers
    $data = $respText | ConvertFrom-Json
    if ($data.error) {
        throw ("ERROR: allocator rejected enrollment: {0}" -f [string]$data.error)
    }
    # Verify response HMAC over payload without response_hmac field
    $received = [string]$data.response_hmac
    $copy = ConvertTo-FrpPlainObject $data
    if ($copy.ContainsKey('response_hmac')) { $copy.Remove('response_hmac') }
    $canonical = Get-FrpCanonicalJson -Object $copy
    $expected = Get-FrpHmacHex -Secret $EnrollmentSecret -Message $canonical
    if (-not $received -or -not (Test-FrpFixedTimeEquals -Left $received -Right $expected -IgnoreCase)) {
        throw 'ERROR: allocator response HMAC verification failed'
    }
    if (-not $data.token_ciphertext) {
        throw 'ERROR: allocator response is missing token_ciphertext'
    }
    $transport = [string]$data.frp_transport
    if (-not $transport) { $transport = 'tcp' }
    $transport = $transport.Trim().ToLowerInvariant()
    if ($transport -ne 'tcp' -and $transport -ne 'wss') {
        throw 'ERROR: allocator returned an unsupported FRP transport'
    }
    $propNames = @($data.PSObject.Properties.Name)
    return @{
        FrpServer       = [string]$data.frp_server
        FrpServerPort   = [int]$data.frp_server_port
        FrpTransport    = $transport
        TokenCiphertext = [string]$data.token_ciphertext
        Services        = @($data.services)
        MgmtStatus      = [string]$data.mgmt_status
        PublicHostname  = [string]$data.public_hostname
        PublicHostnamePresent = ($propNames -contains 'public_hostname')
    }
}

function Get-FrpDefaultServices {
    param(
        [string]$Platform = 'windows',
        [string]$ServicesJson,
        [string]$SshUser
    )
    if ($ServicesJson) {
        $parsed = $ServicesJson | ConvertFrom-Json
        return @($parsed)
    }
    if ($Platform -eq 'windows') {
        return @(
            [pscustomobject]@{
                id         = 'rdp'
                name       = 'RDP'
                preset     = 'rdp'
                protocol   = 'tcp'
                local_ip   = '127.0.0.1'
                local_port = 3389
                enabled    = $true
            }
        )
    }
    if ([string]::IsNullOrWhiteSpace($SshUser)) {
        throw 'ERROR: non-windows default SSH service requires explicit -SshUser / ssh_user (no default root)'
    }
    $ssh = [pscustomobject]@{
        id         = 'ssh'
        name       = 'SSH'
        preset     = 'ssh'
        protocol   = 'tcp'
        local_ip   = '127.0.0.1'
        local_port = 22
        enabled    = $true
        ssh_user   = $SshUser
    }
    return @($ssh)
}

function Complete-FrpZeroTouchPostEnroll {
    param(
        [switch]$SkipStart,
        [switch]$SkipDownload,
        [object]$Services
    )
    $enabledCount = Get-FrpEnabledServiceCount -Services $Services
    if (-not $Services) {
        try {
            $st = Read-FrpClientState
            $Services = $st.services
            $enabledCount = Get-FrpEnabledServiceCount -Services $Services
            if ($st.management_only -eq $true) { $enabledCount = 0 }
        } catch { }
    }

    Set-FrpInstallStatus -Status 'enrolled_incomplete'

    if ($env:FRP_WINDOWS_FAIL_AFTER_ENROLL -eq '1') {
        throw 'ERROR: simulated failure after enroll (FRP_WINDOWS_FAIL_AFTER_ENROLL=1)'
    }

    if (-not $SkipDownload) {
        if ($env:FRP_WINDOWS_SKIP_DOWNLOAD -eq '1') {
            Write-Host 'Skipping FRP download (FRP_WINDOWS_SKIP_DOWNLOAD=1)'
        } else {
            Install-FrpWindowsBinary | Out-Null
        }
    }

    # Persist product CLI + lib modules into ProgramData so a new PowerShell
    # process can run after the bootstrap temp tree is removed.
    if ($script:FrpWindowsSrcRoot) {
        Initialize-FrpDirectories
        $srcClient = Join-Path $script:FrpWindowsSrcRoot 'tools/FrpClient.ps1'
        $srcCmd = Join-Path $script:FrpWindowsSrcRoot 'tools/frp-client.cmd'
        $srcAuto = Join-Path $script:FrpWindowsSrcRoot 'tools/frp-autostart.cmd'
        if (Test-Path -LiteralPath $srcClient) {
            Copy-Item -LiteralPath $srcClient -Destination (Join-Path (Get-FrpToolsDir) 'FrpClient.ps1') -Force
        }
        if (Test-Path -LiteralPath $srcCmd) {
            Copy-Item -LiteralPath $srcCmd -Destination (Join-Path (Get-FrpToolsDir) 'frp-client.cmd') -Force
        }
        if (Test-Path -LiteralPath $srcAuto) {
            Copy-Item -LiteralPath $srcAuto -Destination (Join-Path (Get-FrpToolsDir) 'frp-autostart.cmd') -Force
        }
        $srcLib = Join-Path $script:FrpWindowsSrcRoot 'lib'
        if (Test-Path -LiteralPath $srcLib) {
            $destLib = Get-FrpLibDir
            Get-ChildItem -LiteralPath $srcLib -Filter '*.ps1' -File -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $destLib $_.Name) -Force
            }
        }
    }

    if ($enabledCount -le 0) {
        Write-Host 'Management-only enrollment: no public services; skipping frpc start.'
        Set-FrpInstallStatus -Status 'management_only'
        Write-Host ''
        Write-Host 'Enrollment complete (management-only). Use frp-client info for details.'
        Write-Host 'ENROLL ONCE / RUN MANY TIMES: later starts use existing identity and ports.'
        return 0
    }

    if ($env:FRP_WINDOWS_FAIL_BEFORE_START -eq '1') {
        throw 'ERROR: simulated failure before start (FRP_WINDOWS_FAIL_BEFORE_START=1)'
    }

    # Register product autostart so frpc survives reboot without an
    # interactive login. Required whenever this client has enabled public
    # services. Management-only installs return above and never reach here.
    if ($env:FRP_WINDOWS_SKIP_AUTOSTART -eq '1') {
        Write-Host 'Skipping autostart registration (FRP_WINDOWS_SKIP_AUTOSTART=1)'
    } else {
        try {
            Install-FrpAutostartTask | Out-Null
            if (-not (Test-FrpAutostartHealthy)) {
                throw 'ERROR: autostart task was not registered as a SYSTEM boot task'
            }
            Write-Host ("Registered autostart ({0}): frpc starts at system boot (SYSTEM, no login required)." -f (Get-FrpAutostartTaskName))
        } catch {
            Write-Host ("ERROR: failed to register autostart: {0}" -f $_.Exception.Message)
            Write-Host 'ERROR: enabled public services require reboot persistence without login. This client is not fully installed.'
            return 1
        }
    }

    if (-not $SkipStart) {
        Start-FrpClient | Out-Null
    }

    Set-FrpInstallStatus -Status 'installed'
    Write-Host ''
    Write-Host 'Enrollment complete. Use frp-client info for connection details.'
    Write-Host 'ENROLL ONCE / RUN MANY TIMES: later starts use existing identity and ports.'
    return 0
}

function Invoke-FrpEnrollServices {
    <#
    .SYNOPSIS
      Identity-authenticated apply request (P2.3 management identity, not an
      Enrollment Code). Mirrors the Unix identity-auth branch of
      frp_enroll_services: ECDSA-P256-signed canonical request with
      X-Mgmt-Auth / X-Mgmt-Nonce / X-Mgmt-Signature, response verified with
      the client's stored MAC key. The FRP auth token is never rotated here;
      identity-auth responses must not contain secret material.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)]$Services
    )
    if ($AllocatorUrl -notmatch '^https://') {
        throw 'ERROR: allocator URL must be https://'
    }
    if (-not (Test-FrpIsEnrolled)) {
        throw "ERROR: this client does not have a usable management identity."
    }

    $payload = [ordered]@{
        machine_id = $MachineId
        hostname   = $Hostname
        services   = @($Services)
    }
    $body = Get-FrpCanonicalJson -Object $payload
    $ts = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $nonce = New-FrpNonce
    $message = Get-FrpSignedMessage -MachineId $MachineId -Body $body -Timestamp $ts -Nonce $nonce -Op 'enroll'
    $privatePem = Read-FrpIdentityKey
    $signature = Protect-FrpSignMessage -PrivatePem $privatePem -Message $message
    $privatePem = $null

    $headers = @{
        'X-Mgmt-Auth'      = '1'
        'X-Timestamp'      = [string]$ts
        'X-Mgmt-Nonce'     = $nonce
        'X-Mgmt-Signature' = $signature
    }
    $respText = Invoke-FrpHttpsJson -Method POST -Url $AllocatorUrl -Body $body -Headers $headers
    $data = $respText | ConvertFrom-Json

    if ($data.error) {
        $err = [string]$data.error
        $lowered = $err.ToLowerInvariant()
        if ($lowered -match 'revoked' -or $lowered -match 'does not have a management identity' -or $lowered -match 'unknown client identity') {
            throw ("ERROR: this client's management identity has been revoked. Create a new Enrollment Code on the server, then re-enroll this client. [{0}]" -f $err)
        }
        throw ("ERROR: allocator rejected the change: {0}" -f $err)
    }

    $received = [string]$data.response_hmac
    $copy = ConvertTo-FrpPlainObject $data
    if ($copy.ContainsKey('response_hmac')) { $copy.Remove('response_hmac') }
    $canonical = Get-FrpCanonicalJson -Object $copy
    $mac = Read-FrpIdentityMac
    $expected = Get-FrpHmacHex -Secret $mac -Message $canonical
    if (-not $received -or -not (Test-FrpFixedTimeEquals -Left $received -Right $expected -IgnoreCase)) {
        throw 'ERROR: allocator response HMAC verification failed'
    }
    $propNames = @($data.PSObject.Properties.Name)
    if ($propNames -contains 'ssh_port' -or $propNames -contains 'https_port') {
        throw 'ERROR: allocator returned a legacy SSH/HTTPS response'
    }
    if ($propNames -contains 'token_ciphertext' -or $propNames -contains 'mgmt_mac_key' -or $data.token) {
        throw 'ERROR: allocator returned unexpected secret material'
    }
    if ($propNames -notcontains 'services') {
        throw 'ERROR: allocator response is missing services'
    }
    $transport = [string]$data.frp_transport
    if (-not $transport) { $transport = 'tcp' }
    $transport = $transport.Trim().ToLowerInvariant()
    if ($transport -ne 'tcp' -and $transport -ne 'wss') {
        throw 'ERROR: allocator returned an unsupported FRP transport'
    }
    return @{
        FrpServer      = [string]$data.frp_server
        FrpServerPort  = [int]$data.frp_server_port
        FrpTransport   = $transport
        Services       = @($data.services)
        PublicHostname = [string]$data.public_hostname
        PublicHostnamePresent = ($propNames -contains 'public_hostname')
    }
}

function Invoke-FrpCompensatePreviousServices {
    <#
    .SYNOPSIS
      Re-apply the pre-mutation service set to the allocator after local
      activation failed. Mirrors Unix frp_compensate_previous.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)][string]$Hostname,
        $Services
    )
    if ($env:FRP_WINDOWS_FAIL_SERVER_COMPENSATE -eq '1') {
        throw 'ERROR: simulated server compensation failure (FRP_WINDOWS_FAIL_SERVER_COMPENSATE=1)'
    }
    Write-Host 'Attempting server registry compensation with the previous service set ...'
    $null = Invoke-FrpEnrollServices -AllocatorUrl $AllocatorUrl -MachineId $MachineId `
        -Hostname $Hostname -Services $Services
}

function Invoke-FrpApplyLocalMetadata {
    <#
    .SYNOPSIS
      Apply display-name / ssh_user-only draft changes without contacting the allocator.
    #>
    param($Current, $DraftMap)
    $curMap = ConvertTo-FrpServiceMap -Services $Current.services
    foreach ($sid in @($DraftMap.Keys)) {
        $item = $DraftMap[$sid]
        if ($curMap.Contains($sid) -and $null -ne $curMap[$sid].remote_port -and [string]$curMap[$sid].remote_port -ne '') {
            if ($null -eq $item['remote_port'] -or [string]$item['remote_port'] -eq '') {
                $item['remote_port'] = [int]$curMap[$sid].remote_port
                $DraftMap[$sid] = $item
            }
        }
    }
    $saveArgs = @{
        AllocatorUrl  = [string]$Current.allocator_url
        FrpServer     = [string]$Current.frp_server
        FrpServerPort = [int]$Current.frp_server_port
        Hostname      = [string]$Current.hostname
        MachineId     = [string]$Current.machine_id
        HostId        = [string]$Current.host_id
        Services      = $DraftMap
        Transport     = $(if ($Current.frp_transport) { [string]$Current.frp_transport } else { 'tcp' })
        InstallStatus = $(if ($Current.install_status) { [string]$Current.install_status } else { 'installed' })
    }
    if (Test-FrpObjectHasProperty -Object $Current -Name 'public_hostname') {
        $saveArgs['PublicHostname'] = [string]$Current.public_hostname
    }
    Save-FrpClientState @saveArgs | Out-Null
    Remove-Item -LiteralPath (Get-FrpDraftPath) -Force -ErrorAction SilentlyContinue
    Write-Host 'Applied local changes.'
    Write-Host 'Allocator contacted : NO'
    Write-Host 'frpc restarted      : NO'
    return 0
}

function Invoke-FrpClientApplyDraft {
    <#
    .SYNOPSIS
      Apply pending draft service changes: identity-auth request to the
      allocator, merge allocated ports, regenerate frpc.toml + client-state.json,
      restart frpc if it was running. Existing FRP token is reused (identity
      auth never rotates it). On local activation failure: restore local files
      and compensate the server reservation (Unix-equivalent transaction).
    #>
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
        return (Invoke-FrpClientApplyDraftLocked)
    } finally {
        Exit-FrpClientLock
    }
}

function Invoke-FrpClientApplyDraftLocked {
    if (-not (Test-FrpIsEnrolled)) {
        Write-Host 'ERROR: not enrolled; run install-client.ps1 -ZeroTouch first'
        return 1
    }

    $draftPath = Get-FrpDraftPath
    if (-not (Test-Path -LiteralPath $draftPath)) {
        Write-Host 'No pending changes.'
        return 0
    }

    $current = Read-FrpClientState
    $draftState = Read-FrpDraftState
    $changeClass = Get-FrpStateChangeClass -Current $current -Draft $draftState
    if ($changeClass -eq 'none') {
        Remove-Item -LiteralPath $draftPath -Force -ErrorAction SilentlyContinue
        Write-Host 'No pending changes.'
        return 0
    }

    $draftMap = ConvertTo-FrpServiceMap -Services $draftState.services
    $enabledCount = 0
    foreach ($sid in $draftMap.Keys) { if ($draftMap[$sid]['enabled'] -ne $false) { $enabledCount++ } }
    if ($enabledCount -le 0) {
        Write-Host 'ERROR: at least one enabled service is required.'
        return 1
    }

    if ($changeClass -eq 'local') {
        return (Invoke-FrpApplyLocalMetadata -Current $current -DraftMap $draftMap)
    }

    try {
        $null = Invoke-FrpReconcileReleasedServices
    } catch {
        Write-Host 'ERROR: cannot apply because client synchronization failed.'
        $msg = [string]$_.Exception.Message
        if ($msg) { Write-Host $msg }
        return 1
    }

    if (-not (Test-Path -LiteralPath $draftPath)) {
        Write-Host 'No pending changes.'
        return 0
    }
    $current = Read-FrpClientState
    $draftState = Read-FrpDraftState
    $changeClass = Get-FrpStateChangeClass -Current $current -Draft $draftState
    if ($changeClass -eq 'none') {
        Remove-Item -LiteralPath $draftPath -Force -ErrorAction SilentlyContinue
        Write-Host 'No pending changes.'
        return 0
    }
    if ($changeClass -eq 'local') {
        $draftMap = ConvertTo-FrpServiceMap -Services $draftState.services
        return (Invoke-FrpApplyLocalMetadata -Current $current -DraftMap $draftMap)
    }
    $draftMap = ConvertTo-FrpServiceMap -Services $draftState.services

    $machineId = [string]$current.machine_id
    $hostnameValue = [string]$current.hostname
    $allocatorUrl = [string]$current.allocator_url
    $hostId = [string]$current.host_id
    $priorEnrollList = @(Get-FrpEnrollServiceList -Services $current.services)

    $enrollList = Get-FrpEnrollServiceList -Services $draftMap

    Write-Host ''
    Write-Host 'Authenticating client...'
    Write-Host 'Applying configuration...'

    $serverMutated = $false
    try {
        $result = Invoke-FrpEnrollServices -AllocatorUrl $allocatorUrl -MachineId $machineId `
            -Hostname $hostnameValue -Services $enrollList
        $serverMutated = $true
    } catch {
        Write-Host ("ERROR: apply failed: {0}" -f $_.Exception.Message)
        Write-Host 'The server was not changed; local configuration was not changed.'
        Write-Host 'LOCAL_ROLLBACK=N/A'
        Write-Host 'SERVER_ROLLBACK=N/A'
        return 1
    }

    $emitApplyRollback = {
        param([string]$LocalRollback, [string]$ServerRollback)
        Write-Host ("LOCAL_ROLLBACK={0}" -f $LocalRollback)
        Write-Host ("SERVER_ROLLBACK={0}" -f $ServerRollback)
        if ($ServerRollback -eq 'FAIL') {
            Write-Host 'RECOVERY_REQUIRED=YES'
            Write-Host 'WARNING: server registry may not match local configuration. Reconcile by editing and applying again.'
        }
    }

    foreach ($sid in @($draftMap.Keys)) {
        $item = $draftMap[$sid]
        if ($item['enabled'] -eq $false) { continue }
        $alloc = @($result.Services) | Where-Object { [string]$_.id -eq $sid } | Select-Object -First 1
        if ($null -eq $alloc) {
            Write-Host ("ERROR: allocator response is missing service {0}" -f $sid)
            $localRollback = 'N/A'
            $serverRollback = 'FAIL'
            try {
                Invoke-FrpCompensatePreviousServices -AllocatorUrl $allocatorUrl -MachineId $machineId `
                    -Hostname $hostnameValue -Services $priorEnrollList
                $serverRollback = 'PASS'
            } catch {
                $serverRollback = 'FAIL'
            }
            & $emitApplyRollback $localRollback $serverRollback
            return 1
        }
        $item['remote_port'] = [int]$alloc.remote_port
        $draftMap[$sid] = $item
    }

    $existingToken = Get-FrpTokenFromToml
    if (-not $existingToken) {
        Write-Host 'ERROR: existing FRP client configuration is missing the FRP token; re-enroll this client.'
        $serverRollback = 'FAIL'
        try {
            Invoke-FrpCompensatePreviousServices -AllocatorUrl $allocatorUrl -MachineId $machineId `
                -Hostname $hostnameValue -Services $priorEnrollList
            $serverRollback = 'PASS'
        } catch {
            $serverRollback = 'FAIL'
        }
        & $emitApplyRollback 'N/A' $serverRollback
        return 1
    }

    $transport = [string]$result.FrpTransport
    if (-not $transport) { $transport = [string]$current.frp_transport }
    if (-not $transport) { $transport = 'tcp' }

    Initialize-FrpDirectories
    $backupRoot = Join-Path (Get-FrpBackupDir) ("apply-" + (Get-Date -Format 'yyyyMMddHHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    $snapshotMap = [ordered]@{
        'frpc.toml'         = (Get-FrpTomlPath)
        'client-state.json' = (Get-FrpStatePath)
    }
    foreach ($name in @($snapshotMap.Keys)) {
        $src = $snapshotMap[$name]
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $backupRoot $name) -Force
        }
    }

    $wasRunning = (Get-FrpClientStatus).Running
    $enabledAny = $false
    foreach ($sid in $draftMap.Keys) {
        if ($draftMap[$sid]['enabled'] -ne $false) { $enabledAny = $true; break }
    }
    $saveHostname = @{}
    if ($result.ContainsKey('PublicHostnamePresent') -and $result.PublicHostnamePresent) {
        $saveHostname['PublicHostname'] = [string]$result.PublicHostname
    } elseif (Test-FrpObjectHasProperty -Object $current -Name 'public_hostname') {
        $saveHostname['PublicHostname'] = [string]$current.public_hostname
    }

    try {
        if ($env:FRP_WINDOWS_FAIL_APPLY_ACTIVATE -eq '1') {
            throw 'ERROR: simulated local activation failure (FRP_WINDOWS_FAIL_APPLY_ACTIVATE=1)'
        }
        New-FrpClientToml -ServerAddr $result.FrpServer -ServerPort $result.FrpServerPort -Token $existingToken `
            -HostId $hostId -Services $draftMap -Transport $transport | Out-Null

        Save-FrpClientState -AllocatorUrl $allocatorUrl -FrpServer $result.FrpServer -FrpServerPort $result.FrpServerPort `
            -Hostname $hostnameValue -MachineId $machineId -HostId $hostId -Services $draftMap -Transport $transport `
            -InstallStatus 'installed' @saveHostname | Out-Null

        if ($enabledAny) {
            if ($wasRunning) { Stop-FrpClient | Out-Null }
            # Start when leaving zero-service/management-only, but only if the
            # binary is present (unit tests apply without downloading frpc.exe).
            if (Test-Path -LiteralPath (Get-FrpFrpcPath)) {
                Start-FrpClient | Out-Null
            }
            Install-FrpAutostartTask | Out-Null
            if (-not (Test-FrpAutostartHealthy)) {
                throw 'ERROR: autostart task was not registered as a SYSTEM boot task'
            }
        } else {
            if ($wasRunning) { Stop-FrpClient | Out-Null }
        }
    } catch {
        Write-Host ("ERROR: failed to activate new configuration: {0}" -f $_.Exception.Message)
        Write-Host 'Restoring previous local configuration...'
        $localRollback = 'FAIL'
        try {
            foreach ($name in @($snapshotMap.Keys)) {
                $bak = Join-Path $backupRoot $name
                $dest = $snapshotMap[$name]
                if (Test-Path -LiteralPath $bak) { Copy-Item -LiteralPath $bak -Destination $dest -Force }
            }
            if ($wasRunning) { Start-FrpClient | Out-Null }
            $localRollback = 'PASS'
        } catch {
            $localRollback = 'FAIL'
        }
        $serverRollback = 'FAIL'
        if ($serverMutated) {
            try {
                Invoke-FrpCompensatePreviousServices -AllocatorUrl $allocatorUrl -MachineId $machineId `
                    -Hostname $hostnameValue -Services $priorEnrollList
                $serverRollback = 'PASS'
            } catch {
                $serverRollback = 'FAIL'
            }
        } else {
            $serverRollback = 'N/A'
        }
        & $emitApplyRollback $localRollback $serverRollback
        return 1
    }

    Remove-Item -LiteralPath $draftPath -Force -ErrorAction SilentlyContinue
    Write-Host 'Applied pending changes.'
    Write-Host 'LOCAL_ROLLBACK=N/A'
    Write-Host 'SERVER_ROLLBACK=N/A'
    return 0
}

function Invoke-FrpApplyReconcileRuntime {
    <#
    .SYNOPSIS
      After accepted server reconciliation, converge frpc.toml and runtime.
      Server release is not undone on local runtime failure.
    #>
    param(
        [bool]$DroppedEnabled,
        [bool]$DroppedAny = $false,
        [bool]$HostnameChanged = $false
    )
    if (-not $DroppedEnabled -and -not $DroppedAny -and -not $HostnameChanged) { return }
    if ($DroppedAny -or $DroppedEnabled) {
        if ($env:FRP_CLIENT_HOOK_TOML_REGEN -eq '1') {
            Write-Host 'ERROR: simulated TOML regeneration failure'
            Write-Host 'FAILURE_CLASS=CONFIG_GENERATION_FAILED'
            Write-Host 'RECOVERY_REQUIRED=YES'
            throw 'ERROR: failed to regenerate frpc.toml after server reconciliation.'
        }
        $toml = Get-FrpTomlPath
        if (Test-Path -LiteralPath $toml) {
            $token = Get-FrpTokenFromToml
            if (-not $token) {
                Write-Host 'ERROR: cannot regenerate frpc.toml; FRP token is unavailable.'
                Write-Host 'FAILURE_CLASS=CONFIG_GENERATION_FAILED'
                Write-Host 'RECOVERY_REQUIRED=YES'
                throw 'ERROR: cannot regenerate frpc.toml; FRP token is unavailable.'
            }
            $state = Read-FrpClientState
            $map = ConvertTo-FrpServiceMap -Services $state.services
            $transport = [string]$state.frp_transport
            if (-not $transport) { $transport = 'tcp' }
            New-FrpClientToml -ServerAddr ([string]$state.frp_server) -ServerPort ([int]$state.frp_server_port) `
                -Token $token -HostId ([string]$state.host_id) -Services $map -Transport $transport | Out-Null
        }
    }
    if ($env:FRP_CLIENT_HOOK_ACCESS_REGEN -eq '1') {
        Write-Host 'ERROR: simulated access-info regeneration failure'
        Write-Host 'FAILURE_CLASS=CONFIG_GENERATION_FAILED'
        Write-Host 'RECOVERY_REQUIRED=YES'
        throw 'ERROR: failed to regenerate access-info.txt after server reconciliation.'
    }
    if (-not $DroppedEnabled) { return }
    if ($env:FRP_CLIENT_HOOK_RESTART_FAIL -eq '1') {
        Write-Host 'ERROR: simulated service restart failure'
        Write-Host 'FAILURE_CLASS=FRPC_RESTART_FAILED'
        Write-Host 'RECOVERY_REQUIRED=YES'
        throw 'ERROR: failed to restart frpc after server reconciliation.'
    }
    $state = Read-FrpClientState
    $map = ConvertTo-FrpServiceMap -Services $state.services
    $enabledAny = $false
    foreach ($sid in $map.Keys) {
        if ($map[$sid].enabled -ne $false) { $enabledAny = $true; break }
    }
    if (-not $enabledAny) {
        Set-FrpInstallStatus -Status 'management_only'
        Stop-FrpClient | Out-Null
        return
    }
    $wasRunning = (Get-FrpClientStatus).Running
    if ($wasRunning) {
        Stop-FrpClient | Out-Null
        Start-FrpClient | Out-Null
    }
}

function Invoke-FrpReconcileReleasedServices {
    <#
    .SYNOPSIS
      Reconcile local services and public_hostname against the server registry.
      Returns $true on SUCCESS (change applied), $false on NO_CHANGE.
      Throws on FAILURE. Strict (explicit sync) treats missing identity as failure.
    #>
    param([switch]$Strict)
    if (-not (Test-Path -LiteralPath (Get-FrpStatePath))) { return $false }

    if ($env:FRP_CLIENT_HOOK_RECONCILE_UNREACHABLE -eq '1') {
        Write-Host 'ERROR: allocator unreachable'
        Write-Host 'FAILURE_CLASS=ALLOCATOR_UNREACHABLE'
        throw 'ERROR: allocator unreachable'
    }
    if ($env:FRP_CLIENT_HOOK_RECONCILE_HMAC -eq '1') {
        Write-Host 'ERROR: allocator response HMAC verification failed'
        Write-Host 'FAILURE_CLASS=HMAC_VERIFICATION_FAILED'
        throw 'ERROR: allocator response HMAC verification failed'
    }
    if ($env:FRP_CLIENT_HOOK_RECONCILE_MALFORMED -eq '1') {
        Write-Host 'ERROR: allocator returned a malformed reconcile response'
        Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
        throw 'ERROR: allocator returned a malformed reconcile response'
    }
    if ($env:FRP_CLIENT_HOOK_RECONCILE_STATE -eq '1') {
        Write-Host 'ERROR: failed to update local client state'
        Write-Host 'FAILURE_CLASS=STATE_WRITE_FAILED'
        throw 'ERROR: failed to update local client state'
    }

    if ($env:FRP_SKIP_CONNECTIVITY_CHECK -eq '1' -and -not $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS -and -not $env:FRP_CLIENT_RECONCILE_RESPONSE) {
        return $false
    }

    $state = Read-FrpClientState
    $map = ConvertTo-FrpServiceMap -Services $state.services
    $registryIds = $null
    $hostnamePresent = $false
    $hostnameValue = ''

    if ($env:FRP_CLIENT_RECONCILE_RESPONSE) {
        try {
            $data = $env:FRP_CLIENT_RECONCILE_RESPONSE | ConvertFrom-Json
        } catch {
            Write-Host 'ERROR: allocator returned a malformed reconcile response'
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw 'ERROR: allocator returned a malformed reconcile response'
        }
        if ($data.error) {
            Write-Host ("ERROR: allocator rejected the reconcile request: {0}" -f [string]$data.error)
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw ("ERROR: allocator rejected the reconcile request: {0}" -f [string]$data.error)
        }
        $mac = $null
        try { $mac = Read-FrpIdentityMac } catch { $mac = $null }
        if (-not $mac) {
            Write-Host 'ERROR: management response key is missing'
            Write-Host 'FAILURE_CLASS=MANAGEMENT_IDENTITY'
            throw 'ERROR: management response key is missing'
        }
        $received = [string]$data.response_hmac
        $copy = ConvertTo-FrpPlainObject $data
        if ($copy.ContainsKey('response_hmac')) { $copy.Remove('response_hmac') }
        $canonical = Get-FrpCanonicalJson -Object $copy
        $expected = Get-FrpHmacHex -Secret $mac -Message $canonical
        if (-not $received -or -not (Test-FrpFixedTimeEquals -Left $received -Right $expected -IgnoreCase)) {
            Write-Host 'ERROR: allocator response HMAC verification failed'
            Write-Host 'FAILURE_CLASS=HMAC_VERIFICATION_FAILED'
            throw 'ERROR: allocator response HMAC verification failed'
        }
        if (-not (Test-FrpObjectHasProperty -Object $data -Name 'registry_service_ids')) {
            Write-Host 'ERROR: allocator returned a malformed reconcile response'
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw 'ERROR: allocator returned a malformed reconcile response'
        }
        $registryIds = @()
        if ($null -ne $data.registry_service_ids) {
            $registryIds = @($data.registry_service_ids | ForEach-Object { [string]$_ })
        }
        if (Test-FrpObjectHasProperty -Object $data -Name 'public_hostname') {
            $hostnamePresent = $true
            $hostnameValue = [string]$data.public_hostname
        }
    } elseif ($env:FRP_CLIENT_RECONCILE_REGISTRY_IDS) {
        $parsedIds = $env:FRP_CLIENT_RECONCILE_REGISTRY_IDS | ConvertFrom-Json
        if ($null -eq $parsedIds) {
            $registryIds = @()
        } elseif ($parsedIds -is [string]) {
            $registryIds = @([string]$parsedIds)
        } else {
            $registryIds = @($parsedIds | ForEach-Object { [string]$_ })
        }
        if ($env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME_PRESENT -eq '1') {
            $hostnamePresent = $true
            $hostnameValue = [string]$env:FRP_CLIENT_RECONCILE_PUBLIC_HOSTNAME
        }
    } else {
        if (-not (Test-FrpIsEnrolled)) {
            if ($Strict) {
                Write-Host 'ERROR: this client does not have a usable management identity'
                Write-Host 'FAILURE_CLASS=MANAGEMENT_IDENTITY'
                throw 'ERROR: this client does not have a usable management identity'
            }
            return $false
        }
        $allocatorUrl = [string]$state.allocator_url
        $machineId = [string]$state.machine_id
        $hostnameLocal = [string]$state.hostname
        if (-not $allocatorUrl -or -not $machineId) {
            Write-Host 'ERROR: client state is missing allocator URL or machine ID'
            Write-Host 'FAILURE_CLASS=MANAGEMENT_IDENTITY'
            throw 'ERROR: client state is missing allocator URL or machine ID'
        }
        if ($allocatorUrl -notmatch '^https://') {
            Write-Host 'ERROR: allocator URL must be https://'
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw 'ERROR: allocator URL must be https://'
        }

        $payload = [ordered]@{
            machine_id = $machineId
            hostname   = $hostnameLocal
        }
        $body = Get-FrpCanonicalJson -Object $payload
        $ts = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        $nonce = New-FrpNonce
        $message = Get-FrpSignedMessage -MachineId $machineId -Body $body -Timestamp $ts -Nonce $nonce -Op 'enroll'
        $privatePem = Read-FrpIdentityKey
        $signature = Protect-FrpSignMessage -PrivatePem $privatePem -Message $message
        $privatePem = $null
        $headers = @{
            'X-Mgmt-Auth'      = '1'
            'X-Mgmt-Reconcile' = '1'
            'X-Timestamp'      = [string]$ts
            'X-Mgmt-Nonce'     = $nonce
            'X-Mgmt-Signature' = $signature
        }
        try {
            $respText = Invoke-FrpHttpsJson -Method POST -Url $allocatorUrl -Body $body -Headers $headers
            $data = $respText | ConvertFrom-Json
        } catch {
            Write-Host 'ERROR: allocator unreachable'
            Write-Host 'FAILURE_CLASS=ALLOCATOR_UNREACHABLE'
            throw 'ERROR: allocator unreachable'
        }
        if ($data.error) {
            Write-Host ("ERROR: allocator rejected the reconcile request: {0}" -f [string]$data.error)
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw ("ERROR: allocator rejected the reconcile request: {0}" -f [string]$data.error)
        }
        $received = [string]$data.response_hmac
        $copy = ConvertTo-FrpPlainObject $data
        if ($copy.ContainsKey('response_hmac')) { $copy.Remove('response_hmac') }
        $canonical = Get-FrpCanonicalJson -Object $copy
        $mac = Read-FrpIdentityMac
        $expected = Get-FrpHmacHex -Secret $mac -Message $canonical
        if (-not $received -or -not (Test-FrpFixedTimeEquals -Left $received -Right $expected -IgnoreCase)) {
            Write-Host 'ERROR: allocator response HMAC verification failed'
            Write-Host 'FAILURE_CLASS=HMAC_VERIFICATION_FAILED'
            throw 'ERROR: allocator response HMAC verification failed'
        }
        if (-not (Test-FrpObjectHasProperty -Object $data -Name 'registry_service_ids')) {
            Write-Host 'ERROR: allocator returned a malformed reconcile response'
            Write-Host 'FAILURE_CLASS=INVALID_RESPONSE'
            throw 'ERROR: allocator returned a malformed reconcile response'
        }
        $registryIds = @()
        if ($null -ne $data.registry_service_ids) {
            $registryIds = @($data.registry_service_ids | ForEach-Object { [string]$_ })
        }
        if (Test-FrpObjectHasProperty -Object $data -Name 'public_hostname') {
            $hostnamePresent = $true
            $hostnameValue = [string]$data.public_hostname
        }
    }

    $idSet = @{}
    foreach ($rid in $registryIds) {
        if ($null -ne $rid -and [string]$rid -ne '') { $idSet[[string]$rid] = $true }
    }

    $droppedEnabled = $false
    $droppedAny = $false
    $newMap = [ordered]@{}
    foreach ($sid in @($map.Keys)) {
        if ($idSet.ContainsKey([string]$sid)) {
            $newMap[$sid] = $map[$sid]
            continue
        }
        $droppedAny = $true
        if ($map[$sid].enabled -ne $false) { $droppedEnabled = $true }
    }

    $oldAlias = ''
    if (Test-FrpObjectHasProperty -Object $state -Name 'public_hostname') {
        $oldAlias = ([string]$state.public_hostname).Trim()
    }
    $hostnameChanged = $false
    $saveHostname = @{}
    if ($hostnamePresent) {
        $alias = ([string]$hostnameValue).Trim()
        $saveHostname['PublicHostname'] = $alias
        if ($alias -ne $oldAlias) { $hostnameChanged = $true }
    }

    if (-not $droppedAny -and -not $hostnameChanged) { return $false }

    $enabledLeft = 0
    foreach ($sid in $newMap.Keys) {
        if ($newMap[$sid].enabled -ne $false) { $enabledLeft++ }
    }
    $installStatus = [string]$state.install_status
    if (-not $installStatus) { $installStatus = 'installed' }
    if ($enabledLeft -eq 0) { $installStatus = 'management_only' }

    Save-FrpClientState -AllocatorUrl ([string]$state.allocator_url) -FrpServer ([string]$state.frp_server) `
        -FrpServerPort ([int]$state.frp_server_port) -Hostname ([string]$state.hostname) `
        -MachineId ([string]$state.machine_id) -HostId ([string]$state.host_id) `
        -Services $newMap -Transport ([string]$state.frp_transport) `
        -InstallStatus $installStatus @saveHostname | Out-Null

    $draftPath = Get-FrpDraftPath
    if (Test-Path -LiteralPath $draftPath) {
        try {
            $draft = Read-FrpDraftState
            $draftMap = ConvertTo-FrpServiceMap -Services $draft.services
            $draftNew = [ordered]@{}
            foreach ($sid in @($draftMap.Keys)) {
                if ($idSet.ContainsKey([string]$sid)) { $draftNew[$sid] = $draftMap[$sid] }
            }
            if ($draftNew.Count -eq 0) {
                Remove-Item -LiteralPath $draftPath -Force -ErrorAction SilentlyContinue
            } else {
                Save-FrpDraftServiceMap -ServiceMap $draftNew | Out-Null
            }
        } catch { }
    }

    Invoke-FrpApplyReconcileRuntime -DroppedEnabled $droppedEnabled -DroppedAny $droppedAny -HostnameChanged $hostnameChanged
    return $true
}

function Invoke-FrpClientSync {
    <#
    .SYNOPSIS
      Explicit mutation: reconcile local services against server releases.
    #>
    if (-not (Enter-FrpClientLock)) { return 1 }
    try {
        if (-not (Test-FrpIsEnrolled)) {
            Write-Host 'ERROR: not enrolled; run install-client.ps1 -ZeroTouch first'
            Write-Host 'FAILURE_CLASS=MANAGEMENT_IDENTITY'
            return 1
        }
        try {
            $null = Invoke-FrpReconcileReleasedServices -Strict
        } catch {
            Write-Host ("ERROR: sync failed: {0}" -f $_.Exception.Message)
            return 1
        }
        Write-Host 'Client sync complete.'
        return 0
    } finally {
        Exit-FrpClientLock
    }
}

function Invoke-FrpZeroTouch {
    <#
    .NOTES
      AllocatorUrl / CaSha256 / BootstrapTicket are intentionally NOT
      [Parameter(Mandatory)]: PowerShell's mandatory-parameter binder rejects
      an explicit empty string, but a Finding A crash-safe resume (see
      Test-FrpPendingEnrollMatches below) legitimately needs to call this
      with CaSha256/BootstrapTicket omitted or blank (the CA is already
      pinned to disk and the Bootstrap Ticket must not be re-supplied /
      re-used). Presence is validated explicitly in the body instead, with a
      resume-aware exception for CaSha256/BootstrapTicket.
    #>
    param(
        [string]$AllocatorUrl,
        [string]$CaSha256,
        [string]$BootstrapTicket,
        [string]$Platform = 'windows',
        [string]$ServicesJson,
        [string]$SshUser,
        [string]$Hostname,
        [switch]$SkipStart,
        [switch]$SkipDownload,
        [switch]$UseLocalDefaults
    )

    try {
        if (Test-FrpIsEnrolled) {
            if (Test-FrpCanResumeInstall) {
                Write-Host 'Resuming incomplete install (same identity and ports; ticket not re-redeemed)...'
                return (Complete-FrpZeroTouchPostEnroll -SkipStart:$SkipStart -SkipDownload:$SkipDownload)
            }
            if (Test-FrpIsInstallComplete) {
                Write-Host 'ERROR: this machine is already enrolled.'
                Write-Host 'ENROLL ONCE: refuse re-ticket path. Use: frp-client start'
                Write-Host 'To replace this install, uninstall locally first (server reservations are preserved).'
                return 2
            }
            # Legacy enrolled installs without install_status: treat as complete / refuse re-ticket
            Write-Host 'ERROR: this machine is already enrolled.'
            Write-Host 'ENROLL ONCE: refuse re-ticket path. Use: frp-client start'
            Write-Host 'To replace this install, uninstall locally first (server reservations are preserved).'
            return 2
        }

        # Finding A: Zero-Touch lost-response recovery. Compute the machine
        # id before requiring CA/ticket args (it is deterministic and
        # independent of them) so a lost /bootstrap/redeem or /enroll
        # response can be recovered by resuming from a local crash-safe
        # pending-enrollment transaction instead of re-redeeming a
        # single-use Bootstrap Ticket.
        Initialize-FrpDirectories
        $machineId = Get-FrpOrCreateClientId
        if (-not $Hostname) {
            $Hostname = $env:COMPUTERNAME
            if (-not $Hostname) { $Hostname = [System.Net.Dns]::GetHostName() }
        }
        $Hostname = ([string]$Hostname).Trim()

        $resumePending = $false
        $pending = $null
        if (Test-FrpPendingEnrollMatches -MachineId $machineId) {
            $resumePending = $true
            $pending = Read-FrpPendingEnroll
            if (-not $AllocatorUrl) { $AllocatorUrl = $pending.AllocatorUrl }
        }

        if ($AllocatorUrl -notmatch '^https://') {
            throw 'ERROR: plain HTTP allocator URL is not supported; HTTPS is required'
        }
        if (-not $resumePending) {
            if ([string]::IsNullOrWhiteSpace($CaSha256)) {
                throw 'ERROR: zero-touch setup requires FRP_ALLOCATOR_CA_SHA256 / -CaSha256'
            }
            if ([string]::IsNullOrWhiteSpace($BootstrapTicket)) {
                throw 'ERROR: bootstrap ticket is missing'
            }
        }

        $caPath = Get-FrpAllocatorCaPath
        if ($resumePending -and (Test-Path -LiteralPath $caPath)) {
            # Already pinned by the earlier (crashed) attempt; no CA hash is
            # required to resume.
        } else {
            Write-Host 'Bootstrapping allocator CA (pin verify)...'
            Get-FrpCaCertificate -AllocatorUrl $AllocatorUrl -ExpectedSha256 $CaSha256 | Out-Null
        }

        $enrollmentId = $null
        $enrollmentSecret = $null
        $services = $null
        $publicPem = $null

        if ($resumePending) {
            Write-Host 'A previous enrollment did not finish (response lost or interrupted).'
            Write-Host 'Resuming from local crash-safe recovery state; the Bootstrap Ticket is not reused.'
            $enrollmentId = $pending.EnrollmentId
            $enrollmentSecret = $pending.EnrollmentSecret
            if ([string]::IsNullOrWhiteSpace($enrollmentSecret)) {
                throw 'ERROR: local recovery state is present but unusable. Create a new Enrollment Code and re-enroll this client.'
            }
            $services = @($pending.Services)
            # Identity was generated and saved to disk before the pending
            # record moved to phase=redeemed; reuse it (a fresh keypair would
            # not match what the allocator may have already bound on an
            # "enrolled" exact replay).
            if (-not (Test-Path -LiteralPath (Get-FrpIdentityPubPath))) {
                throw 'ERROR: local recovery state is present but the management identity is missing. Create a new Enrollment Code and re-enroll this client.'
            }
            $publicPem = [System.IO.File]::ReadAllText((Get-FrpIdentityPubPath))
        } else {
            Write-Host 'Redeeming bootstrap ticket...'
            $redeem = Invoke-FrpBootstrapRedeem -AllocatorUrl $AllocatorUrl -Ticket $BootstrapTicket `
                -MachineId $machineId -Hostname $Hostname

            # Ticket redeem is authoritative. Empty services = management-only.
            # Get-FrpDefaultServices is only for explicit local guided UX.
            $services = @($redeem.Services)
            if ($UseLocalDefaults) {
                $services = Get-FrpDefaultServices -Platform $Platform -ServicesJson $ServicesJson -SshUser $SshUser
            } elseif (-not [string]::IsNullOrWhiteSpace($ServicesJson) -and @($services).Count -eq 0) {
                $services = Get-FrpDefaultServices -Platform $Platform -ServicesJson $ServicesJson -SshUser $SshUser
            }
            # else: keep ticket services as-is (including empty)

            Write-Host 'Generating management identity...'
            $id = New-FrpEcdsaIdentity
            Save-FrpIdentityKey -PrivatePem $id.PrivatePem | Out-Null
            Save-FrpIdentityPublic -PublicPem $id.PublicPem | Out-Null
            $publicPem = $id.PublicPem

            $enrollmentId = $redeem.EnrollmentId
            $enrollmentSecret = $redeem.EnrollmentSecret
        }

        $enrollResult = $null
        if ($resumePending -and [string]$pending.Phase -eq 'enrolled' -and $pending.EnrollMeta -and @($pending.AllocatedServices).Count -gt 0) {
            # The server-committed /enroll response was cached locally before
            # the prior crash; finish the local commit without another
            # network round trip or ticket/enrollment-code reuse.
            Write-Host 'Reusing the previously completed enrollment response...'
            $meta = $pending.EnrollMeta
            $transport = [string]$meta.frp_transport
            if (-not $transport) { $transport = 'tcp' }
            $enrollResult = @{
                FrpServer       = [string]$meta.frp_server
                FrpServerPort   = [int]$meta.frp_server_port
                FrpTransport    = $transport
                TokenCiphertext = [string]$meta.token_ciphertext
                Services        = @($pending.AllocatedServices)
                PublicHostname  = [string]$meta.public_hostname
                PublicHostnamePresent = (Test-FrpObjectHasProperty -Object $meta -Name 'public_hostname')
            }
        } else {
            # Persist the enrollment secret and exact request now, before
            # calling /enroll, so a crash after the server commits (but
            # before the response is received or written) can be recovered
            # by an exact replay instead of requiring a new Enrollment Code.
            Save-FrpPendingEnroll -Phase 'redeemed' -MachineId $machineId -Hostname $Hostname `
                -AllocatorUrl $AllocatorUrl -EnrollmentId $enrollmentId -EnrollmentSecret $enrollmentSecret `
                -Services $services | Out-Null

            Write-Host 'Enrolling with allocator...'
            $enrollResult = Invoke-FrpEnroll -AllocatorUrl $AllocatorUrl `
                -EnrollmentId $enrollmentId -EnrollmentSecret $enrollmentSecret `
                -MachineId $machineId -Hostname $Hostname -Services $services -PublicPem $publicPem

            $enrollMeta = @{
                frp_server       = $enrollResult.FrpServer
                frp_server_port  = $enrollResult.FrpServerPort
                frp_transport    = $enrollResult.FrpTransport
                token_ciphertext = $enrollResult.TokenCiphertext
            }
            if ($enrollResult.ContainsKey('PublicHostnamePresent') -and $enrollResult.PublicHostnamePresent) {
                $enrollMeta['public_hostname'] = [string]$enrollResult.PublicHostname
            }
            Save-FrpPendingEnroll -Phase 'enrolled' -MachineId $machineId -Hostname $Hostname `
                -AllocatorUrl $AllocatorUrl -EnrollmentId $enrollmentId -EnrollmentSecret $enrollmentSecret `
                -Services $services -EnrollMeta $enrollMeta -AllocatedServices $enrollResult.Services | Out-Null

            if ($env:FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL -eq '1') {
                # Test-only: simulate a crash/lost response after the
                # allocator has committed the enrollment and the response
                # was cached locally, but before any further local commit
                # step runs.
                throw 'ERROR: simulated crash after enrollment commit (FRP_WINDOWS_HOOK_CRASH_AFTER_ENROLL=1)'
            }
        }

        $token = Unprotect-FrpTokenPbkdf2 -Ciphertext $enrollResult.TokenCiphertext -Secret $enrollmentSecret
        $mac = Get-FrpDerivedMacKey -Secret $enrollmentSecret -MachineId $machineId
        Save-FrpIdentityMac -MacKeyHex $mac | Out-Null

        $merged = Merge-FrpAllocatedPorts -LocalServices $services -AllocatedList $enrollResult.Services
        $hostId = ($machineId.Substring(0, [Math]::Min(12, $machineId.Length)))

        $saveHostname = @{}
        if ($enrollResult.ContainsKey('PublicHostnamePresent') -and $enrollResult.PublicHostnamePresent) {
            $saveHostname['PublicHostname'] = [string]$enrollResult.PublicHostname
        }
        Save-FrpClientState -AllocatorUrl $AllocatorUrl -FrpServer $enrollResult.FrpServer `
            -FrpServerPort $enrollResult.FrpServerPort -Hostname $Hostname -MachineId $machineId `
            -HostId $hostId -Services $merged -Transport $enrollResult.FrpTransport `
            -InstallStatus 'enrolled_incomplete' @saveHostname | Out-Null

        New-FrpClientToml -ServerAddr $enrollResult.FrpServer -ServerPort $enrollResult.FrpServerPort `
            -Token $token -HostId $hostId -Services $merged -Transport $enrollResult.FrpTransport | Out-Null

        # Wipe plaintext token from local variable ASAP
        $token = $null

        # Local state (client-state.json + frpc.toml + management identity,
        # all written above) is now committed. The crash-safe recovery
        # transaction is no longer needed; clear it so it is never replayed
        # against a future, unrelated Enrollment Code.
        Clear-FrpPendingEnroll

        return (Complete-FrpZeroTouchPostEnroll -SkipStart:$SkipStart -SkipDownload:$SkipDownload -Services $merged)
    } finally {
        Clear-FrpSecretEnv
    }
}
