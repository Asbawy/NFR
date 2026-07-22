#!/usr/bin/env bash
# NFR Standalone Binary Builder (Bash)
set -e

echo "[+] Building NFR standalone binary..."

if ! python3 -c "import PyInstaller" 2>/dev/null; then
    echo "[-] PyInstaller not found. Installing pyinstaller..."
    python3 -m pip install pyinstaller
fi

echo "[+] Running PyInstaller..."
python3 -m PyInstaller --onefile --name=nfr --clean NFR.py

if [ -f "dist/nfr" ]; then
    echo ""
    echo "[+] SUCCESS! Standalone binary created at: dist/nfr"
else
    echo ""
    echo "[+] Build completed. Check 'dist' directory."
fi
