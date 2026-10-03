$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
. (Join-Path $PSScriptRoot 'Ensure-Uv.ps1')
$uvExe = Get-ProjectUv
$configPath = '"' + (Join-Path $taskRoot 'config.json') + '"'
# uv still owns the locked environment; pythonw removes a persistent console window.
Start-Process -FilePath $uvExe -ArgumentList @('run', '--locked', 'pythonw', '-m', 'ssh_gate', '--config', $configPath) -WorkingDirectory $taskRoot -WindowStyle Hidden
