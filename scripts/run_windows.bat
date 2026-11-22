@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PROJECT_DIR=%%~fI"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PY_CMD=py -3"
    set "PYW_CMD=pyw -3"
) else (
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        echo Python 3 was not found in PATH. Install Python 3.10+ from https://www.python.org/downloads/
        pause
        exit /b 1
    )
    set "PY_CMD=python"
    where pythonw >nul 2>nul
    if %errorlevel%==0 (
        set "PYW_CMD=pythonw"
    ) else (
        set "PYW_CMD=python"
    )
)

%PY_CMD% -c "import webview" >nul 2>nul
if %errorlevel% neq 0 (
    echo Installing Windows GUI dependency ^(pywebview^)...
    %PY_CMD% -m pip install -r "%PROJECT_DIR%\requirements-windows.txt"
    if %errorlevel% neq 0 (
        echo Failed to install pywebview. Launching with Edge/Chrome app mode fallback...
    )
)

start "" %PYW_CMD% "%PROJECT_DIR%\dsb\app.py"
