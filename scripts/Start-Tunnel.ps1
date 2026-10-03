$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
$keyPointer = [IntPtr]::Zero
$savedEnv = @{}
$envNames = @('CONTROL_PLANE_API_KEY', 'CONTROL_PLANE_TUNNEL_ID', 'MCP_SERVER_URL', 'MCP_COMMAND', 'HEALTH_LISTEN_ADDR', 'NO_PROXY')
foreach ($name in $envNames) { $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $config = Get-Content -LiteralPath 'config.json' -Raw -Encoding UTF8 | ConvertFrom-Json
    $endpoint = 'http://127.0.0.1:' + $config.listen_port
    # Explicitly bypass system/enterprise proxy for the loopback health check (Windows PS 5.1).
    $localRequest = [Net.WebRequest]::Create($endpoint + '/healthz')
    $localRequest.Proxy = $null
    $localRequest.Timeout = 3000
    $localResponse = $localRequest.GetResponse()
    try {
        $localReader = New-Object IO.StreamReader($localResponse.GetResponseStream())
        try { $health = $localReader.ReadToEnd() | ConvertFrom-Json }
        finally { $localReader.Dispose() }
    } finally { $localResponse.Dispose() }
    if ($health.service -ne 'ssh-gate') { throw 'Unexpected service on backend port.' }
    $configuredClient = [Environment]::ExpandEnvironmentVariables($config.tunnel.client_path)
    $clientPath = if ([IO.Path]::IsPathRooted($configuredClient)) { $configuredClient } else { Join-Path $taskRoot $configuredClient }
    if (-not (Test-Path -LiteralPath $clientPath)) {
        $found = Get-Command tunnel-client.exe -ErrorAction SilentlyContinue
        if ($found) { $clientPath = $found.Source }
        else { throw 'Download the full Windows tunnel-client from https://platform.openai.com/settings/organization/tunnels or https://github.com/openai/tunnel-client/releases/latest and set tunnel.client_path in config.json.' }
    }
    $tunnelId = $config.tunnel.id
    if (-not $tunnelId) {
        $tunnelId = Read-Host 'Tunnel ID from OpenAI Platform (tunnel_ + 32 lowercase hex characters)'
    }
    if ($tunnelId -notmatch '^tunnel_[0-9a-f]{32}$') { throw 'Invalid tunnel ID.' }
    if (-not $config.tunnel.id) {
        $config.tunnel.id = $tunnelId
        $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath 'config.json' -Encoding UTF8
    }
    $secureKey = Read-Host 'OpenAI tunnel runtime API key (not stored on disk)' -AsSecureString
    $keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
    $env:CONTROL_PLANE_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
    if (-not $env:CONTROL_PLANE_API_KEY) { throw 'Runtime API key is empty.' }
    $env:CONTROL_PLANE_TUNNEL_ID = $tunnelId
    $env:MCP_SERVER_URL = $endpoint + '/mcp'
    Remove-Item Env:MCP_COMMAND -ErrorAction SilentlyContinue
    $healthPort = [int]$config.tunnel.health_port
    if ($healthPort -lt 1024 -or $healthPort -gt 65535 -or $healthPort -eq [int]$config.listen_port) { throw 'Invalid tunnel health port.' }
    $env:HEALTH_LISTEN_ADDR = '127.0.0.1:' + $healthPort
    $env:NO_PROXY = if ($savedEnv['NO_PROXY']) { $savedEnv['NO_PROXY'] + ',127.0.0.1,localhost' } else { '127.0.0.1,localhost' }
    Write-Host ('Local tunnel health UI: http://127.0.0.1:' + $healthPort + '/ui')
    Write-Host 'Keep this terminal and the approval window open. Ctrl+C stops the tunnel.'
    # Supported env-var HTTP binding: no public listener, model call, or profile with secrets.
    & $clientPath run
    if ($LASTEXITCODE -ne 0) { throw ('tunnel-client exited with code ' + $LASTEXITCODE) }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    foreach ($name in $envNames) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
    if ($keyPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer) }
    if ($secureKey) { $secureKey.Dispose() }
}
