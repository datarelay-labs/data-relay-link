# test-security.ps1 — no permanent global TLS bypass patterns; quoting hygiene
$ErrorActionPreference = 'Stop'

function Assert-FrpTrue {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERT: $Message" }
}
function Write-FrpTestPass { param([string]$Name) Write-Host "PASS $Name" }

$lib = Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path 'windows'
$files = Get-ChildItem -Path $lib -Recurse -Include *.ps1, *.cmd
$bad = @()
foreach ($f in $files) {
    $text = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $text) { continue }
    # Naked permanent bypass: Callback = {$true} (no restore pattern).
    if ($text -match 'ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}') {
        $bad += $f.FullName
    }
    if ($text -match '(?i)(Invoke-RestMethod|\birm\b)\s*\|\s*(Invoke-Expression|\biex\b)') {
        # Allow documentation that forbids the pattern.
        $lines = $text -split "`n"
        $hit = $false
        foreach ($line in $lines) {
            if ($line -match '(?i)(Invoke-RestMethod|\birm\b)\s*\|\s*(Invoke-Expression|\biex\b)') {
                if ($line -match '(?i)no\s+irm|never\s+irm|not\s+.*irm') { continue }
                $hit = $true
                break
            }
        }
        if ($hit) { $bad += ("iex:{0}" -f $f.FullName) }
    }
}
Assert-FrpTrue ($bad.Count -eq 0) ("forbidden patterns: " + ($bad -join ', '))

# FrpTls must restore previous callback (finally).
$tls = Get-Content -LiteralPath (Join-Path $lib 'lib\FrpTls.ps1') -Raw
Assert-FrpTrue ($tls -match 'finally') 'tls finally present'
Assert-FrpTrue ($tls -match 'ServerCertificateValidationCallback = \$previous') 'tls restores callback'
Assert-FrpTrue ($tls -match '\$previousCallback') 'ca fetch restores previousCallback'

# Hostname validation must never short-circuit with -or $true near MatchesHostname.
Assert-FrpTrue ($tls -notmatch 'MatchesHostname[^\r\n]*-or\s*\$true') 'no MatchesHostname -or $true'
Assert-FrpTrue ($tls -notmatch '-or\s*\$true') 'no -or $true in FrpTls.ps1'
Assert-FrpTrue ($tls -match 'function\s+Test-FrpCertificateHostname') 'hostname helper present'
Assert-FrpTrue ($tls -match 'Test-FrpCertificateHostname') 'validator uses hostname helper'
Assert-FrpTrue ($tls -match 'FRP_WINDOWS_FORCE_CURL') 'allocator JSON curl is opt-in, not default'
Assert-FrpTrue ($tls -notmatch 'Start-Process -FilePath ''curl.exe'' -ArgumentList \$args') 'allocator JSON does not Start-Process curl ArgumentList'
Assert-FrpTrue ($tls -notmatch '\$build\.ChainPolicy\.Revision\s*=') 'does not assign X509ChainPolicy.Revision'

Write-FrpTestPass 'test-security'
