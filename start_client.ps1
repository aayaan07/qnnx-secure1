# Client + Local Proxy startup script for local development on Windows
# Run from the Client/ directory: .\start_client.ps1

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  QVPN Client - Local Proxy Startup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Check for virtual environment ---
$venvPython = ".\venv\Scripts\python.exe"
$systemPython = "python"

if (Test-Path $venvPython) {
    $python = $venvPython
    Write-Host "[OK] Using virtual environment: $venvPython" -ForegroundColor Green
} else {
    Write-Host "[INFO] No venv found. Creating one..." -ForegroundColor Yellow
    & $systemPython -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create virtual environment." -ForegroundColor Red
        exit 1
    }
    $python = $venvPython
    Write-Host "[OK] Virtual environment created." -ForegroundColor Green
}

# --- Step 2: Install dependencies ---
Write-Host ""
Write-Host "[STEP 1/2] Installing dependencies..." -ForegroundColor Yellow
& $python -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] pip install failed." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Dependencies installed." -ForegroundColor Green

# --- Step 3: Show what's running ---
Write-Host ""
Write-Host "[STEP 2/2] Starting QVPN Client + Local HTTP Proxy..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Local Proxy (browser proxy) : http://127.0.0.1:8080" -ForegroundColor Cyan
Write-Host "  QVPN Client data interface  : 127.0.0.1:8282 (internal)" -ForegroundColor Cyan
Write-Host "  Status endpoint             : http://127.0.0.1:8283/status" -ForegroundColor Cyan
Write-Host "  Gateway VPN tunnel          : 127.0.0.1:5151" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Configure your browser HTTP proxy to:" -ForegroundColor Yellow
Write-Host "    Proxy Server : 127.0.0.1" -ForegroundColor White
Write-Host "    Port         : 8080" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Run the headless client which starts the proxy and VPN client core
& $python run_headless_test.py
