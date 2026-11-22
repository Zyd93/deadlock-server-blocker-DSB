$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
Push-Location $ProjectDir

try {
    python -m pip install --upgrade pip
    python -m pip install -r requirements-windows.txt pyinstaller
    python -m unittest discover -s tests -v

    pyinstaller `
        --noconfirm `
        --clean `
        --onefile `
        --noconsole `
        --uac-admin `
        --icon "assets/icon.ico" `
        --name "DeadlockServerBlocker-DSB" `
        --add-data "ui;ui" `
        --add-data "assets;assets" `
        --collect-all webview `
        dsb/app.py

    Write-Host ""
    Write-Host "Build complete: $ProjectDir\dist\DeadlockServerBlocker-DSB.exe"
}
finally {
    Pop-Location
}
