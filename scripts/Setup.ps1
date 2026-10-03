$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot

try {
    . (Join-Path $PSScriptRoot 'Ensure-Uv.ps1')
    $uvExe = Get-ProjectUv -Install
    & $uvExe sync --locked
    if ($LASTEXITCODE -ne 0) { throw 'uv dependency synchronization failed.' }
    & $uvExe run --locked python -c 'import webview; print("Python and pywebview ready.")'
    if ($LASTEXITCODE -ne 0) { throw 'pywebview dependency validation failed.' }
    if (Test-Path -LiteralPath 'config.json') {
        Write-Host 'Existing config.json preserved. Edit it directly if necessary.'
    } else {
        $config = Get-Content -LiteralPath 'config.example.json' -Raw -Encoding UTF8 | ConvertFrom-Json
        $config.servers = @()
        $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath 'config.json' -Encoding UTF8
    }
    & $uvExe run --locked python -c 'from pathlib import Path; from ssh_gate.config import load_config; c=load_config(Path("config.json")); print("Configuration valid. No SSH command was executed.")'
    if ($LASTEXITCODE -ne 0) { throw 'Please correct config.json and rerun setup.' }
    Write-Host 'Setup complete. Run Start-App.cmd. Manage connections and the tunnel in the application.' -ForegroundColor Green
    Write-Host 'Microsoft Edge WebView2 Runtime is required: https://developer.microsoft.com/microsoft-edge/webview2/'
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
