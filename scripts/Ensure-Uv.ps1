function Get-ProjectUv {
    param([switch]$Install)
    $found = Get-Command uv.exe -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    $defaultUv = Join-Path $env:USERPROFILE '.local\bin\uv.exe'
    if (Test-Path -LiteralPath $defaultUv) { return $defaultUv }
    if (-not $Install) { throw 'uv not found. Run Setup.cmd first.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $installer = Join-Path ([IO.Path]::GetTempPath()) ('uv-install-' + [guid]::NewGuid().ToString('N') + '.ps1')
    try {
        Invoke-WebRequest -Uri 'https://astral.sh/uv/install.ps1' -OutFile $installer -UseBasicParsing
        & $installer | Out-Host
        if (-not (Test-Path -LiteralPath $defaultUv)) { throw 'uv installer did not produce the expected executable. Install uv manually, then rerun Setup.cmd.' }
        return $defaultUv
    } finally {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    }
}
