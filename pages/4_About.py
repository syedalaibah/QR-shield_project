from __future__ import annotations

import streamlit as st

from qrshield.ui import apply_style, hero

apply_style("About QRShield")
hero(
    "About QRShield",
    "A Python-based cybersecurity education project that demonstrates safe QR payload inspection and explainable URL risk heuristics.",
    chips=["PYTHON", "STREAMLIT", "OPENCV", "SQLITE"],
)

st.markdown("""
### Project overview
QRShield is a local-first QR-code phishing and payload risk analyzer. It decodes QR images, examines payload structure, identifies common warning patterns, and presents the reasoning behind its score.

### Main objectives
- Decode QR codes from uploaded images or camera captures.
- Inspect URL characteristics without visiting the destination.
- Explain detected indicators rather than showing only a score.
- Preserve redacted scan records locally for review.
- Export investigation results as JSON and HTML reports.

### Technology stack
| Technology | Purpose |
|---|---|
| Python | Application logic and URL analysis |
| Streamlit | Interactive multi-page web interface |
| OpenCV | QR-code image decoding |
| Pillow + qrcode | Image handling and sample QR generation |
| Plotly + Pandas | Dashboard charts and history table |
| SQLite | Local scan-history database |

### Important limitations
QRShield uses offline heuristics, not a production threat-intelligence service. A link may be malicious even if no rules are triggered, and a legitimate link can trigger a warning. The score is intended for learning and triage, not as a definitive security verdict. No QR payload is executed and no URL is opened automatically.

### Suggested future improvements
- Add optional VirusTotal or other reputation API integration with explicit consent and API-key management.
- Add a larger labelled URL dataset and evaluate a machine-learning model.
- Add unit tests for more URL edge cases and safe domain parsing.
- Package the app for deployment with appropriate secret handling and access controls.
""")
