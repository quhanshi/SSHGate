param([string]$DestinationRoot = '')
$ErrorActionPreference = 'Stop'
$taskRoot = if ($DestinationRoot) { $DestinationRoot } else { Split-Path -Parent $PSScriptRoot }
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('ssh-gate-download-' + [guid]::NewGuid().ToString('N'))
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $networkOptions = @{}
    if ($env:APP_DOWNLOAD_PROXY) {
        $proxyUri = [Uri]$env:APP_DOWNLOAD_PROXY
        $safeProxy = [UriBuilder]$proxyUri
        $safeProxy.UserName = ''; $safeProxy.Password = ''
        $networkOptions['Proxy'] = $safeProxy.Uri
        if ($proxyUri.UserInfo) {
            $parts = $proxyUri.UserInfo -split ':', 2
            $username = [Uri]::UnescapeDataString($parts[0])
            $password = if ($parts.Length -gt 1) { [Uri]::UnescapeDataString($parts[1]) } else { '' }
            $networkOptions['ProxyCredential'] = [System.Management.Automation.PSCredential]::new($username, (ConvertTo-SecureString $password -AsPlainText -Force))
        }
    } elseif ($env:APP_DOWNLOAD_DIRECT -eq 'true') {
        [Net.WebRequest]::DefaultWebProxy = $null
    }
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $headers = @{ 'User-Agent' = 'SSH-Gate-Setup'; 'Accept' = 'application/vnd.github+json' }
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/openai/tunnel-client/releases/latest' -Headers $headers @networkOptions
    $cpuArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $platform = if ($cpuArch -eq 'ARM64') { 'windows-arm64' } elseif ($cpuArch -eq 'AMD64') { 'windows-amd64' } else { throw 'Only Windows x64 / ARM64 is supported.' }
    $archiveName = 'tunnel-client-' + $release.tag_name + '-' + $platform + '.zip'
    $archive = @($release.assets | Where-Object { $_.name -eq $archiveName })
    $checksum = @($release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' })
    if ($archive.Count -ne 1 -or $checksum.Count -ne 1) { throw 'Official release archive or checksums not found. Download from the Platform Tunnels page instead.' }
    foreach ($asset in @($archive[0], $checksum[0])) {
        if ($asset.browser_download_url -notmatch '^https://github\.com/openai/tunnel-client/releases/download/') { throw 'Unexpected download origin.' }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile (Join-Path $tempRoot $asset.name) -UseBasicParsing @networkOptions
    }
    $pattern = '^([0-9a-fA-F]{64})\s+\*?' + [regex]::Escape($archiveName) + '$'
    $lines = @(Get-Content -LiteralPath (Join-Path $tempRoot 'SHA256SUMS.txt') | Where-Object { $_ -match $pattern })
    if ($lines.Count -ne 1) { throw 'Archive checksum entry missing or ambiguous.' }
    [void]($lines[0] -match $pattern)
    $expectedHash = $Matches[1]
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $tempRoot $archiveName)).Hash
    if ($actualHash -ne $expectedHash) { throw 'SHA256 verification failed. No executable installed.' }
    $unpacked = Join-Path $tempRoot 'unpacked'
    Expand-Archive -LiteralPath (Join-Path $tempRoot $archiveName) -DestinationPath $unpacked
    $binary = @(Get-ChildItem -LiteralPath $unpacked -Filter 'tunnel-client.exe' -File -Recurse)
    if ($binary.Count -ne 1) { throw 'Official client executable not found.' }
    $destination = Join-Path $taskRoot 'bin'
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    # Preserve the executable's official companions and notices together.
    Get-ChildItem -LiteralPath $binary[0].Directory.FullName | Copy-Item -Destination $destination -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $tempRoot 'SHA256SUMS.txt') -Destination $destination -Force
    $release.tag_name | Set-Content -LiteralPath (Join-Path $destination 'downloaded-release.txt') -Encoding UTF8
    & (Join-Path $destination 'tunnel-client.exe') --version
    if ($LASTEXITCODE -ne 0) { throw 'Downloaded client could not start.' }
    Write-Host 'Official tunnel client downloaded and checksum verified.' -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
