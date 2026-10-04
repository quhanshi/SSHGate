$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Build the Windows executable on Windows.' }
    . (Join-Path $PSScriptRoot 'Ensure-Uv.ps1')
    $uvExe = Get-ProjectUv -Install
    & $uvExe sync --locked --group build
    if ($LASTEXITCODE -ne 0) { throw 'Build dependency synchronization failed.' }
    & $uvExe run --locked --group build pyinstaller --clean --noconfirm SSHGate.spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    $destination = Join-Path $taskRoot 'dist\SSHGate'
    Copy-Item -LiteralPath 'README.md', 'config.example.json' -Destination $destination -Force
    if (Test-Path -LiteralPath (Join-Path $taskRoot 'bin')) {
        Copy-Item -LiteralPath (Join-Path $taskRoot 'bin') -Destination $destination -Recurse -Force
    }
    # Do not copy config.json, logs, passwords or the user's private keys into a distributable build.
    Write-Host ('Build complete: ' + (Join-Path $destination 'SSHGate.exe')) -ForegroundColor Green
    Write-Host 'Distribute the entire SSHGate directory. WebView2 Runtime is still required.'
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
