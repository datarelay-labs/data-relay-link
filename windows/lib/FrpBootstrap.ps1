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
    return @{
        FrpServer       = [string]$data.frp_server
        FrpServerPort   = [int]$data.frp_server_port
        FrpTransport    = $transport
        TokenCiphertext = [string]$data.token_ciphertext
        Services        = @($data.services)
        MgmtStatus      = [string]$data.mgmt_status
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
        if (Test-Path -LiteralPath $srcClient) {
            Copy-Item -LiteralPath $srcClient -Destination (Join-Path (Get-FrpToolsDir) 'FrpClient.ps1') -Force
        }
        if (Test-Path -LiteralPath $srcCmd) {
            Copy-Item -LiteralPath $srcCmd -Destination (Join-Path (Get-FrpToolsDir) 'frp-client.cmd') -Force
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

    if (-not $SkipStart) {
        Start-FrpClient | Out-Null
    }

    Set-FrpInstallStatus -Status 'installed'
    Write-Host ''
    Write-Host 'Enrollment complete. Use frp-client info for connection details.'
    Write-Host 'ENROLL ONCE / RUN MANY TIMES: later starts use existing identity and ports.'
    return 0
}

function Invoke-FrpZeroTouch {
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$CaSha256,
        [Parameter(Mandatory = $true)][string]$BootstrapTicket,
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

        if ($AllocatorUrl -notmatch '^https://') {
            throw 'ERROR: plain HTTP allocator URL is not supported; HTTPS is required'
        }
        if ([string]::IsNullOrWhiteSpace($CaSha256)) {
            throw 'ERROR: zero-touch setup requires FRP_ALLOCATOR_CA_SHA256 / -CaSha256'
        }
        if ([string]::IsNullOrWhiteSpace($BootstrapTicket)) {
            throw 'ERROR: bootstrap ticket is missing'
        }

        Initialize-FrpDirectories
        Write-Host 'Bootstrapping allocator CA (pin verify)...'
        Get-FrpCaCertificate -AllocatorUrl $AllocatorUrl -ExpectedSha256 $CaSha256 | Out-Null

        $machineId = Get-FrpOrCreateClientId
        if (-not $Hostname) {
            $Hostname = $env:COMPUTERNAME
            if (-not $Hostname) { $Hostname = [System.Net.Dns]::GetHostName() }
        }
        $Hostname = ([string]$Hostname).Trim()

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

        Write-Host 'Enrolling with allocator...'
        $enroll = Invoke-FrpEnroll -AllocatorUrl $AllocatorUrl `
            -EnrollmentId $redeem.EnrollmentId -EnrollmentSecret $redeem.EnrollmentSecret `
            -MachineId $machineId -Hostname $Hostname -Services $services -PublicPem $id.PublicPem

        $token = Unprotect-FrpTokenPbkdf2 -Ciphertext $enroll.TokenCiphertext -Secret $redeem.EnrollmentSecret
        $mac = Get-FrpDerivedMacKey -Secret $redeem.EnrollmentSecret -MachineId $machineId
        Save-FrpIdentityMac -MacKeyHex $mac | Out-Null

        $merged = Merge-FrpAllocatedPorts -LocalServices $services -AllocatedList $enroll.Services
        $hostId = ($machineId.Substring(0, [Math]::Min(12, $machineId.Length)))

        $enabledCount = Get-FrpEnabledServiceCount -Services $merged
        $initialStatus = $(if ($enabledCount -le 0) { 'enrolled_incomplete' } else { 'enrolled_incomplete' })

        Save-FrpClientState -AllocatorUrl $AllocatorUrl -FrpServer $enroll.FrpServer `
            -FrpServerPort $enroll.FrpServerPort -Hostname $Hostname -MachineId $machineId `
            -HostId $hostId -Services $merged -Transport $enroll.FrpTransport `
            -InstallStatus $initialStatus | Out-Null

        New-FrpClientToml -ServerAddr $enroll.FrpServer -ServerPort $enroll.FrpServerPort `
            -Token $token -HostId $hostId -Services $merged -Transport $enroll.FrpTransport | Out-Null

        # Wipe plaintext token from local variable ASAP
        $token = $null

        return (Complete-FrpZeroTouchPostEnroll -SkipStart:$SkipStart -SkipDownload:$SkipDownload -Services $merged)
    } finally {
        Clear-FrpSecretEnv
    }
}
