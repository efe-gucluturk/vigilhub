<#
.SYNOPSIS
  One-command launcher: initialises the DB on first run, then starts the API and dashboard.
  Press Ctrl+C to stop both.
#>
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$venvBin = Join-Path $root ".venv\Scripts"
$vigilhub = if (Test-Path (Join-Path $venvBin "vigilhub.exe")) { Join-Path $venvBin "vigilhub.exe" } else { "vigilhub" }
if (-not (Get-Command $vigilhub -ErrorAction SilentlyContinue)) {
    Write-Error "vigilhub not found. Run: python -m venv .venv; .venv\Scripts\activate; pip install -e '.[dev]'"
}

$dbFile = Join-Path $root "vigilhub.db"
$keyFile = Join-Path $root ".vigilhub_key"
if (-not (Test-Path $dbFile) -or -not (Test-Path $keyFile)) {
    Write-Host "First run: initialising database..." -ForegroundColor Cyan
    & $vigilhub init-db
    if ($LASTEXITCODE -ne 0) { Write-Error "init-db failed" }
}
if (Test-Path $keyFile) {
    Write-Host ""
    Write-Host "Your API key (paste it into the dashboard):" -ForegroundColor Yellow
    Write-Host ("  " + (Get-Content $keyFile -Raw).Trim()) -ForegroundColor Green
    Write-Host ""
}

if (-not (Test-Path (Join-Path $root "frontend\node_modules"))) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
    Push-Location (Join-Path $root "frontend")
    try { npm install; if ($LASTEXITCODE -ne 0) { Write-Error "npm install failed" } } finally { Pop-Location }
}

$procs = @()
try {
    Write-Host "API:       http://127.0.0.1:8000" -ForegroundColor Cyan
    $procs += Start-Process -FilePath $vigilhub -ArgumentList "serve", "--host", "127.0.0.1", "--port", "8000" `
        -WorkingDirectory $root -NoNewWindow -PassThru
    Write-Host "Dashboard: http://127.0.0.1:3000  (Ctrl+C to stop)" -ForegroundColor Cyan
    $procs += Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm run dev" `
        -WorkingDirectory (Join-Path $root "frontend") -NoNewWindow -PassThru

    while ($true) {
        Start-Sleep -Seconds 1
        if ($procs | Where-Object { $_.HasExited }) {
            Write-Warning "A server exited; shutting down."
            break
        }
    }
}
finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            # /T kills the whole tree (cmd -> npm -> node)
            & taskkill.exe /PID $p.Id /T /F | Out-Null
        }
    }
    Write-Host "Stopped." -ForegroundColor Cyan
}
