# QRShield — QR-Code Phishing & Payload Risk Analyzer

QRShield is a Python + Streamlit cybersecurity education project. It decodes QR-code images, analyzes URL and payload warning signs using explainable offline rules, stores redacted scan history locally in SQLite, and exports JSON/HTML reports.

> **Important:** QRShield never opens a destination or executes a QR payload. It does not query an online reputation service. The score is a heuristic learning aid, not a guarantee that a website is safe or malicious.

## Features

- Multi-page Streamlit dashboard with custom dark/neon styling and CSS animations
- QR-code decoding from PNG/JPG uploads and camera input
- Manual payload/URL analysis
- Explainable warnings for HTTP, URL shorteners, literal IP addresses, IDN/punycode, lookalike brand wording, credential-like terms, unusual ports, and sensitive query parameters
- Risk score from 0–100 with Low / Moderate / High / Critical labels
- Sample Security Lab with generated QR-code images
- Local SQLite scan history, filtering, detail view, and delete-history control
- Downloadable JSON and HTML reports
- Masks common token/password query values and Wi-Fi QR passwords before displaying or storing reports

## Requirements

- Windows 10/11, macOS, or Linux
- Python **3.14 supported** (this guide is configured for your installed Python 3.14.0). Current Streamlit releases support Python 3.14; compatible recent versions of the project dependencies will be selected by pip.
- Internet connection during the one-time dependency installation
- VS Code is optional; Command Prompt or PowerShell is enough

## Windows setup — from the beginning

### 1. Install Python

You already have Python 3.14.0 installed, so you do not need to install Python 3.11 or 3.12. If Python is not installed on another computer, install a current version from the official Python website:

https://www.python.org/downloads/

During installation, tick **“Add python.exe to PATH”**. Open a new Command Prompt and check:

```bat
py --version
```

If the `py` command is unavailable, try:

```bat
python --version
```

### 2. Download and extract the project

Download `QRShield_Project.zip`, then right-click it and choose **Extract All**. You should have a folder named `QRShield_Project` containing `app.py`, `requirements.txt`, `pages`, and `qrshield`.

### 3. Open a terminal in the project folder

In File Explorer, open the extracted `QRShield_Project` folder. Click the address bar, type `cmd`, and press Enter. A Command Prompt will open in the correct folder.

Check that you are in the right place:

```bat
dir
```

You should see `app.py` and `requirements.txt` in the output.

### 4. Create a virtual environment

Run these commands one by one in Command Prompt:

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The command `py -m venv .venv` uses your default Python installation (Python 3.14.0 on your computer). Do **not** use `py -3.11` unless you have Python 3.11 installed.

### 5. Run QRShield

Keep the virtual environment activated and run:

```bat
python -m streamlit run app.py
```

Streamlit should open QRShield in your browser. If it does not open automatically, use the **Local URL** printed in the terminal, usually:

```text
http://localhost:8501
```

Do not close the terminal while using the app.

### Optional: automatic first-time setup

After Python is installed and the ZIP has been extracted, double-click `Setup_and_Run_QRShield.bat`. It creates a virtual environment, installs the requirements, and launches the app. An internet connection is needed for the initial package installation. The equivalent commands are shown above if you prefer to run them yourself.

## Windows PowerShell version

If you prefer PowerShell, open a terminal in the extracted folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The `py -m venv .venv` command uses the default Python launcher version, which is Python 3.14.0 on your computer. If PowerShell blocks the activation script, use the environment's Python directly instead (no activation needed):

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Running the project again later

Every time you want to launch QRShield again:

1. Open Command Prompt in the `QRShield_Project` folder.
2. Run:

```bat
.venv\Scripts\activate.bat
python -m streamlit run app.py
```

When you finish, press **Ctrl+C** in the terminal to stop the app. After setup, you can also double-click `Run_QRShield.bat` to start it again.

## How to use the app

1. **Command Center:** See scan totals, risk distribution, and scan activity.
2. **QR Scanner:** Upload a PNG/JPG image, use the camera, or paste a QR payload/URL. Select **Analyze** to run the checks.
3. **Security Lab:** Pick a bundled demonstration, view/download its QR code, and run the analysis. The examples do not need to be opened in a browser.
4. **Scan History:** Filter earlier results and select a record to inspect it again. You can delete all history from the page after confirming.
5. **About QRShield:** Review the project objectives, technologies, and limitations.

## Project folder structure

```text
QRShield_Project/
│   app.py
│   requirements.txt
│   README.md
│   Run_QRShield.bat
│   Setup_and_Run_QRShield.bat
│   .gitignore
│
├── pages/
│   ├── 1_QR_Scanner.py
│   ├── 2_Security_Lab.py
│   ├── 3_Scan_History.py
│   └── 4_About.py
│
├── qrshield/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── database.py
│   ├── qr_utils.py
│   ├── reporting.py
│   └── ui.py
│
├── tests/
│   └── test_analyzer.py
│
└── .streamlit/
    └── config.toml
```

The `data/qrshield_history.db` SQLite file is automatically created the first time the app runs. It is not required to exist before launch.

## Run the tests (optional)

From the project folder, with the virtual environment activated:

```bat
python -m unittest discover -s tests -v
```

## Troubleshooting

**`py` or `python` is not recognized:** Reinstall Python and select “Add python.exe to PATH”, then open a new terminal.

**`No module named streamlit`:** Activate the virtual environment and run `pip install -r requirements.txt` again.

**The QR cannot be read:** Use a higher-resolution image with the whole QR visible, avoid glare, and try PNG/JPG. Alternatively paste the decoded payload manually.

**Port 8501 is busy:** Run `python -m streamlit run app.py --server.port 8502` and open `http://localhost:8502`.

**To reset the app's stored history:** Use the Scan History page's delete option. The local database is in `data/qrshield_history.db`.

## Academic project notes

Suggested title: **QRShield: Explainable QR-Code Phishing & Payload Risk Analyzer**

Suggested one-line description: A Python cybersecurity application that decodes QR codes, examines embedded payloads with explainable offline risk rules, and produces a local investigation report without automatically visiting the destination.

### Limitations to mention in a presentation

- URL checks are heuristic and can have false positives and false negatives.
- The application does not verify domain reputation, website content, TLS certificates, or whether a destination is currently malicious.
- A QR code can contain phone, email, Wi-Fi, plain-text, and other payloads—not only website URLs.
- The history database is local to the folder where the app runs. If the folder is copied, the database can be copied too.
