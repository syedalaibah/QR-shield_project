@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo QRShield virtual environment was not found.
    echo First follow the setup commands in README.md.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
python -m streamlit run app.py
pause
