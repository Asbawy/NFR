# NFR Standalone Binary Builder (PowerShell)
Write-Host "[+] Building NFR standalone binary..." -ForegroundColor Cyan

# Check PyInstaller installation
python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] PyInstaller not found. Installing pyinstaller..." -ForegroundColor Yellow
    python -m pip install pyinstaller
}

Write-Host "[+] Running PyInstaller..." -ForegroundColor Cyan
python -m PyInstaller --onefile --name=nfr --clean NFR.py

if ($LASTEXITCODE -eq 0) {
    $binaryPath = Join-Path (Get-Location) "dist\nfr.exe"
    if (Test-Path $binaryPath) {
        Write-Host "`n[+] SUCCESS! Standalone binary created at: $binaryPath" -ForegroundColor Green
    } else {
        Write-Host "`n[+] Build completed. Check 'dist' directory." -ForegroundColor Green
    }
} else {
    Write-Host "`n[-] Build failed with exit code $LASTEXITCODE" -ForegroundColor Red
}
