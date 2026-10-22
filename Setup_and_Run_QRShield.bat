@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo QRShield - First-Time Setup and Launch
echo ==============================================

echo Using your default Python installation:
py --version
if errorlevel 1 (
    echo The Python launcher was not found. Trying python...
    python --version
    if errorlevel 1 (
        echo Python was not found. Install Python and add it to PATH.
        pause
        exit /b 1
    )
)

if not exist ".venv\Scripts\python.exe" (
    py -m venv .venv
    if errorlevel 1 (
        echo The py launcher could not create the environment. Trying python...
        python -m venv .venv
    )
    if errorlevel 1 (
        echo Could not create the virtual environment.
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo Could not activate the virtual environment.
    pause
    exit /b 1
)

python --version
python -m pip install --upgrade pip
if errorlevel 1 (
    echo pip upgrade failed. Check your internet connection and try again.
    pause
    exit /b 1
)

python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed. Check your internet connection and package error message.
    pause
    exit /b 1
)

echo Starting QRShield in your browser...
python -m streamlit run app.py
pause
