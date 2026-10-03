$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
try {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Install Node.js 22.18+ or 24 LTS to rebuild React source. Normal app startup does not need Node.js.' }
    $npmExe = (Get-Command npm.cmd -ErrorAction Stop).Source
    Set-Location -LiteralPath (Join-Path $taskRoot 'frontend')
    & $npmExe ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    & $npmExe run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    Write-Host 'Frontend assets updated. Use Start-App.cmd for source startup; rebuild an existing EXE with Build-App.cmd.' -ForegroundColor Green
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
