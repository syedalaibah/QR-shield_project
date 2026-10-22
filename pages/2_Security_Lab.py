from __future__ import annotations

import streamlit as st

from qrshield.analyzer import analyze_payload
from qrshield.database import save_scan
from qrshield.qr_utils import generate_qr_png
from qrshield.ui import apply_style, hero, render_analysis

apply_style("Security Lab")
hero(
    "Security Lab / Safe Demonstrations",
    "Explore how the rule engine reacts to harmless, preselected sample payloads. The examples use reserved or well-known demonstration domains and are not opened.",
    chips=["SAMPLE DATA", "RULE EXPLANATIONS", "DOWNLOADABLE QR"],
)

samples = {
    "Baseline HTTPS URL": {
        "payload": "https://example.com/",
        "description": "A simple HTTPS URL with no deliberately suspicious pattern. A low score is not a safety guarantee.",
    },
    "HTTP + IP address + login wording": {
        "payload": "http://192.0.2.10/login?verify=1",
        "description": "A documentation-only IP address combined with HTTP and login-like wording to demonstrate multiple rules.",
    },
    "URL shortener example": {
        "payload": "https://bit.ly/example-demo-link",
        "description": "A well-known shortening domain is flagged because the final destination is concealed. This example is not opened.",
    },
    "Brand-lookalike pattern (reserved domain)": {
        "payload": "http://paypal-security-check.verify-account.login.example.invalid/verify",
        "description": "A reserved .invalid domain contains brand-like wording to demonstrate the lookalike-domain rule. It is not a real service.",
    },
    "Sensitive query value (masked in history)": {
        "payload": "https://example.com/callback?access_token=demo-secret-value",
        "description": "Demonstrates how the app flags and masks token-like query parameters in displayed and saved reports.",
    },
    "Plain text message": {
        "payload": "Welcome to the cybersecurity lab. No website link is included.",
        "description": "Shows how ordinary text is classified without treating it as a website URL.",
    },
}

selected = st.selectbox("Choose a sample scenario", list(samples.keys()))
sample = samples[selected]
left, right = st.columns([1.15, 1])
with left:
    st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>SELECTED SCENARIO</div><h3 style='margin-top:10px'>" + selected + "</h3><p class='qs-muted'>" + sample["description"] + "</p></div>", unsafe_allow_html=True)
    st.markdown("**Sample payload**")
    st.code(sample["payload"], language=None)
    run = st.button("Run sample analysis", type="primary", use_container_width=True)
with right:
    try:
        qr_png = generate_qr_png(sample["payload"])
        st.image(qr_png, caption="Generated sample QR code", width=250)
        st.download_button("⬇ Download sample QR image", data=qr_png, file_name="qrshield_sample_qr.png", mime="image/png", use_container_width=True)
    except ValueError as error:
        st.error(str(error))

if run:
    result = analyze_payload(sample["payload"])
    save_scan(result, source=f"Security Lab: {selected}")
    st.session_state.qrshield_lab_result = result
    st.session_state.qrshield_lab_counter = st.session_state.get("qrshield_lab_counter", 0) + 1
    st.success("Sample analyzed and added to local history.")

if st.session_state.get("qrshield_lab_result"):
    st.divider()
    st.subheader("Sample analysis results")
    render_analysis(st.session_state.qrshield_lab_result, key_prefix=f"lab_{st.session_state.get('qrshield_lab_counter', 1)}")

st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>RISK SCORING METHODOLOGY</div><h3 style='margin-top:10px'>Why is the score rule-based?</h3><p class='qs-muted'>Every warning has a reason and adds a defined number of points. For example, HTTP adds a warning because it does not encrypt the connection; a shortener adds a warning because it hides the eventual destination. Points are capped at 100. These are indicators for review, not a definitive malware verdict.</p></div>", unsafe_allow_html=True)
