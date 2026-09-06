# FrpTls.ps1 — CA pin bootstrap + pinned HTTPS JSON client.
# One-shot insecure fetch ONLY for /ca.crt bytes; never leave a global TLS bypass.

if ((Test-Path variable:script:FrpTlsLoaded) -and $script:FrpTlsLoaded) { return }
$script:FrpTlsLoaded = $true

function Get-FrpAllocatorOrigin {
    param([Parameter(Mandatory = $true)][string]$AllocatorUrl)
    $u = [string]$AllocatorUrl
    if ($u -notmatch '^https://') {
        throw 'ERROR: allocator URL must be https://'
    }
    if ($u -match '[\r\n\t ]') {
        throw 'ERROR: allocator URL contains illegal whitespace'
    }
    try {
        $uri = [Uri]$u
    } catch {
        throw 'ERROR: invalid allocator URL'
    }
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        throw 'ERROR: allocator URL must be an https:// URL with a host'
    }
    $builder = New-Object System.UriBuilder $uri
    $builder.Path = ''
    $builder.Query = $null
    $builder.Fragment = $null
    # UriBuilder may keep trailing empty path as /
    $origin = $builder.Uri.GetLeftPart([System.UriPartial]::Authority)
    return $origin
}

function Normalize-FrpCaSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $t = ([string]$Value).Trim().ToLowerInvariant()
    if ($t.StartsWith('sha256:')) { $t = $t.Substring(7) }
    $t = $t -replace '[^0-9a-f]', ''
    if ($t.Length -ne 64) {
        throw 'ERROR: invalid CA fingerprint'
    }
    return $t
}

function Get-FrpCertificateDerSha256 {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $der = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    return Get-FrpSha256Hex -Bytes $der
}

function Get-FrpCaCertificate {
    <#
    .SYNOPSIS
      Fetch /ca.crt with a request-local insecure callback, verify DER SHA-256, install to certs dir.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$AllocatorUrl,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [string]$DestinationPath
    )
    if (-not $DestinationPath) { $DestinationPath = Get-FrpAllocatorCaPath }
    $expected = Normalize-FrpCaSha256 -Value $ExpectedSha256

    if (Test-Path -LiteralPath $DestinationPath) {
        $existing = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($DestinationPath)
        try {
            $actual = Get-FrpCertificateDerSha256 -Certificate $existing
            if ($actual -ne $expected) {
                throw 'ERROR: CA fingerprint mismatch'
            }
            return $DestinationPath
        } finally {
            $existing.Dispose()
        }
    }

    $origin = Get-FrpAllocatorOrigin -AllocatorUrl $AllocatorUrl
    $caUrl = "$origin/ca.crt"

    $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    $bytes = $null
    try {
        # Temporary bypass ONLY for this CA download. Restored in finally.
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true
        }

        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                $p = Start-Process -FilePath 'curl.exe' -ArgumentList @(
                    '--fail', '--silent', '--show-error', '--max-time', '30',
                    '--proto', '=https', '--insecure', '-o', $tmp, $caUrl
                ) -Wait -PassThru -NoNewWindow
                if ($p.ExitCode -ne 0) {
                    throw "ERROR: allocator TLS CA certificate could not be downloaded from $caUrl"
                }
                $bytes = [System.IO.File]::ReadAllBytes($tmp)
            } finally {
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            }
        } else {
            # .NET WebClient / HttpWebRequest with temporary callback
            $req = [System.Net.HttpWebRequest]::Create($caUrl)
            $req.Method = 'GET'
            $req.Timeout = 30000
            $req.ReadWriteTimeout = 30000
            $resp = $req.GetResponse()
            try {
                $stream = $resp.GetResponseStream()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $bytes = $ms.ToArray()
            } finally {
                $resp.Close()
            }
        }
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
    }

    if (-not $bytes -or $bytes.Length -lt 32) {
        throw "ERROR: allocator TLS CA certificate could not be downloaded from $caUrl"
    }

    $cert = $null
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$bytes)
    } catch {
        throw 'ERROR: downloaded allocator CA is not a valid X.509 certificate'
    }
    try {
        $actual = Get-FrpCertificateDerSha256 -Certificate $cert
        if ($actual -ne $expected) {
            throw 'ERROR: CA fingerprint mismatch'
        }
        $dir = Split-Path -Parent $DestinationPath
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $tmpOut = Join-Path $dir ("allocator-ca.crt." + [guid]::NewGuid().ToString('N') + '.tmp')
        # Prefer PEM text if original looks like PEM; otherwise write DER-as-exported cert PEM.
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($text -match 'BEGIN CERTIFICATE') {
            [System.IO.File]::WriteAllBytes($tmpOut, $bytes)
        } else {
            $pem = "-----BEGIN CERTIFICATE-----`n"
            $b64 = [Convert]::ToBase64String($bytes)
            for ($i = 0; $i -lt $b64.Length; $i += 64) {
                $len = [Math]::Min(64, $b64.Length - $i)
                $pem += $b64.Substring($i, $len) + "`n"
            }
            $pem += "-----END CERTIFICATE-----`n"
            [System.IO.File]::WriteAllText($tmpOut, $pem)
        }
        Move-Item -LiteralPath $tmpOut -Destination $DestinationPath -Force
        return $DestinationPath
    } finally {
        if ($cert) { $cert.Dispose() }
    }
}

function Test-FrpDnsNameMatchesHostname {
    param(
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Hostname
    )
    $p = $Pattern.Trim().TrimEnd('.').ToLowerInvariant()
    $h = $Hostname.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($p) -or [string]::IsNullOrWhiteSpace($h)) { return $false }
    if ($p -eq $h) { return $true }
    # RFC 6125 single-label wildcard: *.example.com matches a.example.com, not example.com or a.b.example.com
    if ($p.StartsWith('*.') -and $p.Length -gt 2) {
        $suffix = $p.Substring(1) # ".example.com"
        if (-not $h.EndsWith($suffix)) { return $false }
        $prefix = $h.Substring(0, $h.Length - $suffix.Length)
        if ([string]::IsNullOrEmpty($prefix)) { return $false }
        if ($prefix.Contains('.')) { return $false }
        return $true
    }
    return $false
}

function Read-FrpAsn1Length {
    param([byte[]]$Data, [int]$Offset)
    if ($Offset -ge $Data.Length) { throw 'asn1 truncated' }
    $b = $Data[$Offset]
    if ($b -lt 0x80) {
        return @{ Length = [int]$b; Next = $Offset + 1 }
    }
    $n = $b -band 0x7F
    if ($n -lt 1 -or $n -gt 4) { throw 'asn1 length unsupported' }
    if (($Offset + $n) -ge $Data.Length) { throw 'asn1 truncated' }
    $len = 0
    for ($i = 1; $i -le $n; $i++) {
        $len = ($len -shl 8) -bor $Data[$Offset + $i]
    }
    return @{ Length = [int]$len; Next = $Offset + 1 + $n }
}

function Get-FrpCertificateSanEntries {
    <#
    .SYNOPSIS
      Parse SubjectAltName (2.5.29.17) into DNS names and IP addresses. Fail closed on parse errors.
    #>
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $dnsNames = New-Object System.Collections.Generic.List[string]
    $ipAddresses = New-Object System.Collections.Generic.List[string]
    $ext = $null
    foreach ($e in $Certificate.Extensions) {
        if ($e.Oid -and $e.Oid.Value -eq '2.5.29.17') { $ext = $e; break }
    }
    if ($null -eq $ext) {
        return @{ DnsNames = @(); IpAddresses = @(); Present = $false }
    }

    $raw = $ext.RawData
    if ($null -eq $raw -or $raw.Length -lt 2) {
        return @{ DnsNames = @(); IpAddresses = @(); Present = $true }
    }

    try {
        $idx = 0
        if ($raw[$idx] -ne 0x30) { throw 'san not sequence' }
        $idx++
        $seqLen = Read-FrpAsn1Length -Data $raw -Offset $idx
        $idx = $seqLen.Next
        $end = $idx + $seqLen.Length
        if ($end -gt $raw.Length) { throw 'asn1 truncated' }

        while ($idx -lt $end) {
            $tag = $raw[$idx]
            $idx++
            $lenInfo = Read-FrpAsn1Length -Data $raw -Offset $idx
            $idx = $lenInfo.Next
            $len = $lenInfo.Length
            if (($idx + $len) -gt $end) { throw 'asn1 truncated' }
            $slice = New-Object byte[] $len
            [Array]::Copy($raw, $idx, $slice, 0, $len)
            $idx += $len

            # context-specific primitive: dNSName [2], iPAddress [7]
            if ($tag -eq 0x82) {
                $dnsNames.Add([System.Text.Encoding]::ASCII.GetString($slice))
            } elseif ($tag -eq 0x87) {
                if ($len -eq 4 -or $len -eq 16) {
                    $ipAddresses.Add(([System.Net.IPAddress]::new($slice)).ToString())
                }
            }
        }
    } catch {
        return @{ DnsNames = @(); IpAddresses = @(); Present = $true; ParseFailed = $true }
    }

    return @{
        DnsNames    = @($dnsNames)
        IpAddresses = @($ipAddresses)
        Present     = $true
        ParseFailed = $false
    }
}

function Test-FrpCertificateHostname {
    <#
    .SYNOPSIS
      Verify leaf certificate hostname (DNS/IP SAN, CN fallback). Fail closed on mismatch.
    #>
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Hostname
    )
    $hostName = ([string]$Hostname).Trim()
    if ([string]::IsNullOrWhiteSpace($hostName)) { return $false }

    # Prefer platform MatchesHostname when available (never short-circuit to always-true).
    try {
        $mi = [System.Security.Cryptography.X509Certificates.X509Certificate2].GetMethod(
            'MatchesHostname',
            [type[]]@([string], [bool], [bool])
        )
        if ($null -eq $mi) {
            $mi = [System.Security.Cryptography.X509Certificates.X509Certificate2].GetMethod(
                'MatchesHostname',
                [type[]]@([string])
            )
        }
        if ($null -ne $mi) {
            if ($mi.GetParameters().Length -eq 3) {
                return [bool]$mi.Invoke($Certificate, @($hostName, $true, $true))
            }
            return [bool]$mi.Invoke($Certificate, @($hostName))
        }
    } catch {
        # Fall through to manual verification.
    }

    $parsedIp = $null
    $isIp = [System.Net.IPAddress]::TryParse($hostName, [ref]$parsedIp)
    $san = Get-FrpCertificateSanEntries -Certificate $Certificate
    if ($san.ParseFailed) { return $false }

    $hasDnsOrIpSan = ($san.DnsNames.Count -gt 0) -or ($san.IpAddresses.Count -gt 0)
    if ($hasDnsOrIpSan) {
        if ($isIp) {
            foreach ($ipText in $san.IpAddresses) {
                $sanIp = $null
                if ([System.Net.IPAddress]::TryParse($ipText, [ref]$sanIp)) {
                    if ($sanIp.Equals($parsedIp)) { return $true }
                }
            }
            return $false
        }
        foreach ($dns in $san.DnsNames) {
            if (Test-FrpDnsNameMatchesHostname -Pattern $dns -Hostname $hostName) { return $true }
        }
        return $false
    }

    # CN fallback only when no DNS/IP SAN present.
    if ($isIp) { return $false }
    $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    if ([string]::IsNullOrWhiteSpace($cn)) {
        # Subject CN attribute as last resort when GetNameInfo empty and no SAN
        $subject = $Certificate.Subject
        if ($subject -match '(?i)(?:^|,)\s*CN\s*=\s*([^,]+)') {
            $cn = $Matches[1].Trim().Trim('"')
        }
    }
    if ([string]::IsNullOrWhiteSpace($cn)) { return $false }
    return (Test-FrpDnsNameMatchesHostname -Pattern $cn -Hostname $hostName)
}

function New-FrpPinnedServerCertificateValidator {
    param([Parameter(Mandatory = $true)][string]$CaPath)
    $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CaPath)
    $caHandle = $ca
    $validator = {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        try {
            if ($null -eq $certificate) { return $false }
            $serverCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate
            $build = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $build.ChainPolicy.Revision = [System.Security.Cryptography.X509Certificates.X509ChainPolicy]::Default.Revision
            $build.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
            $build.ChainPolicy.ExtraStore.Add($caHandle) | Out-Null
            $build.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $ok = $build.Build($serverCert)
            if (-not $ok) { return $false }
            $trusted = $false
            foreach ($el in $build.ChainElements) {
                if ($el.Certificate.Thumbprint -eq $caHandle.Thumbprint) { $trusted = $true; break }
                # Also compare raw DER equality
                $a = $el.Certificate.GetRawCertData()
                $b = $caHandle.GetRawCertData()
                if ($a.Length -eq $b.Length) {
                    $same = $true
                    for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { $same = $false; break } }
                    if ($same) { $trusted = $true; break }
                }
            }
            if (-not $trusted) { return $false }

            # Hostname required after CA trust; fail closed if hostname cannot be determined.
            $hostName = $null
            if ($sender -is [System.Net.HttpWebRequest]) {
                $uri = ([System.Net.HttpWebRequest]$sender).RequestUri
                if ($null -ne $uri) { $hostName = $uri.Host }
            } elseif ($null -ne $sender) {
                try {
                    $uriProp = $sender.RequestUri
                    if ($null -ne $uriProp) { $hostName = $uriProp.Host }
                } catch { }
            }
            if ([string]::IsNullOrWhiteSpace($hostName)) { return $false }
            return (Test-FrpCertificateHostname -Certificate $serverCert -Hostname $hostName)
        } catch {
            return $false
        }
    }.GetNewClosure()
    return @{ Callback = $validator; Ca = $caHandle }
}

function Invoke-FrpHttpsJson {
    <#
    .SYNOPSIS
      HTTPS JSON request using the pinned project CA. Never installs a permanent bypass.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$Body,
        [hashtable]$Headers,
        [string]$CaPath,
        [int]$TimeoutSec = 30
    )
    if ($Url -notmatch '^https://') {
        throw 'ERROR: only https:// URLs are supported'
    }
    if (-not $CaPath) { $CaPath = Get-FrpAllocatorCaPath }
    if (-not (Test-Path -LiteralPath $CaPath)) {
        throw "ERROR: trusted allocator CA is missing ($CaPath)"
    }

    # Windows curl.exe (schannel) does not honor --cacert the way OpenSSL curl
    # does, and Start-Process -ArgumentList splits "-H Content-Type: application/json"
    # into a bogus host named "application". Use the request-local .NET pin by
    # default. Opt into curl only with FRP_WINDOWS_FORCE_CURL=1.
    $forceDotNetHttp = ($env:FRP_WINDOWS_FORCE_DOTNET_HTTP -eq '1')
    $forceCurl = ($env:FRP_WINDOWS_FORCE_CURL -eq '1')
    $useCurl = (-not $forceDotNetHttp) -and $forceCurl -and (Get-Command curl.exe -ErrorAction SilentlyContinue)
    if ($useCurl) {
        $tmpBody = $null
        $tmpResp = [System.IO.Path]::GetTempFileName()
        $args = @(
            '--silent', '--show-error', '--fail',
            '--max-time', ([string]$TimeoutSec),
            '--cacert', $CaPath,
            '-X', $Method.ToUpperInvariant(),
            '-H', 'Content-Type: application/json'
        )
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                $args += @('-H', ("{0}: {1}" -f $k, $Headers[$k]))
            }
        }
        if ($null -ne $Body) {
            $tmpBody = [System.IO.Path]::GetTempFileName()
            [System.IO.File]::WriteAllText($tmpBody, $Body, [System.Text.UTF8Encoding]::new($false))
            $args += @('--data-binary', "@$tmpBody")
        }
        $args += @('-o', $tmpResp, $Url)
        try {
            # Call operator keeps each argument intact. Do not use Start-Process
            # -ArgumentList here: headers with colons/spaces get split.
            & curl.exe @args
            if ($LASTEXITCODE -ne 0) {
                throw 'ERROR: allocator request failed'
            }
            return [System.IO.File]::ReadAllText($tmpResp, [System.Text.Encoding]::UTF8)
        } finally {
            if ($tmpBody) { Remove-Item -LiteralPath $tmpBody -Force -ErrorAction SilentlyContinue }
            Remove-Item -LiteralPath $tmpResp -Force -ErrorAction SilentlyContinue
        }
    }

    # .NET path with request-local validation callback (restored afterwards).
    $pin = New-FrpPinnedServerCertificateValidator -CaPath $CaPath
    $previous = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $pin.Callback
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method.ToUpperInvariant()
        $req.ContentType = 'application/json'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                if ($k -match '^(Content-Type)$') { continue }
                $req.Headers[$k] = [string]$Headers[$k]
            }
        }
        if ($null -ne $Body -and $Method.ToUpperInvariant() -ne 'GET') {
            $payload = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentLength = $payload.Length
            $rs = $req.GetRequestStream()
            try { $rs.Write($payload, 0, $payload.Length) } finally { $rs.Close() }
        }
        $resp = $req.GetResponse()
        try {
            $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
            try { return $sr.ReadToEnd() } finally { $sr.Close() }
        } finally {
            $resp.Close()
        }
    } catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response) {
            $sr = New-Object System.IO.StreamReader($ex.Response.GetResponseStream(), [System.Text.Encoding]::UTF8)
            try {
                $errBody = $sr.ReadToEnd()
                if ($errBody) { return $errBody }
            } finally { $sr.Close() }
        }
        throw 'ERROR: allocator request failed'
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previous
        if ($pin.Ca) { $pin.Ca.Dispose() }
    }
}
