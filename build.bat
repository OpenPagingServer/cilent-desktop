@echo off
cd /d "%~dp0"

py -m pip install --upgrade pip
if errorlevel 1 exit /b 1

py -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

py -m pip install pyinstaller
if errorlevel 1 exit /b 1

py -m PyInstaller --noconfirm --clean OpenPagingServerDesktop.spec
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\OpenPagingServerClient.exe