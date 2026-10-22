from __future__ import annotations

import streamlit as st

from qrshield.analyzer import analyze_payload, redact_sensitive_payload
from qrshield.database import save_scan
from qrshield.qr_utils import decode_qr_image
from qrshield.ui import apply_style, hero, render_analysis

apply_style("QR Scanner")
hero(
    "QR Scanner & Payload Analyzer",
    "Upload a QR image, use your camera, or paste the decoded content. QRShield analyzes the payload locally and never opens the destination.",
    chips=["PNG / JPG", "CAMERA INPUT", "EXPLAINABLE FINDINGS"],
)

if "qrshield_latest_result" not in st.session_state:
    st.session_state.qrshield_latest_result = None
if "qrshield_scan_counter" not in st.session_state:
    st.session_state.qrshield_scan_counter = 0

uploaded_tab, text_tab = st.tabs(["📷  Image / camera scan", "⌨️  Paste payload"])

with uploaded_tab:
    st.markdown("<div class='qs-panel'><h3>1. Provide a QR image</h3><p class='qs-muted'>Use a clear, well-lit image. Supported formats: PNG, JPG, JPEG. Max size: 10 MB.</p></div>", unsafe_allow_html=True)
    image_col, help_col = st.columns([1.2, 1])
    with image_col:
        uploaded = st.file_uploader("Upload QR-code image", type=["png", "jpg", "jpeg"], key="qr_image_upload")
        camera = st.camera_input("Or take a picture with your camera", key="qr_camera_upload")
    with help_col:
        st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>SCANNER NOTES</div><p>• Keep the QR code in focus.</p><p>• Avoid reflections and heavy cropping.</p><p>• If decoding fails, try a sharper image or paste the decoded text in the other tab.</p><p class='qs-muted'>Images are processed in the app session and are not stored in scan history.</p></div>", unsafe_allow_html=True)

    image_file = uploaded if uploaded is not None else camera
    if image_file is not None:
        image_bytes = image_file.getvalue()
        st.image(image_bytes, caption="Selected QR image", width=320)
        try:
            with st.spinner("Decoding QR pattern..."):
                decoded_items = decode_qr_image(image_bytes)
            if not decoded_items:
                st.warning("No readable QR code was found. Try a clearer image, or use the Paste payload tab.")
            else:
                st.success(f"Decoded {len(decoded_items)} QR payload(s). Review the selected payload before analysis.")
                selected_index = st.selectbox(
                    "Choose the QR code to analyze",
                    options=list(range(len(decoded_items))),
                    format_func=lambda index: f"QR code {index + 1}: {redact_sensitive_payload(decoded_items[index])[:65]}{'…' if len(redact_sensitive_payload(decoded_items[index])) > 65 else ''}",
                    key="decoded_qr_choice",
                )
                preview = decoded_items[selected_index]
                st.markdown("**Decoded payload preview**")
                safe_preview = redact_sensitive_payload(preview)
                st.code(safe_preview[:1500] + ("…" if len(safe_preview) > 1500 else ""), language=None)
                if st.button("Analyze decoded payload", type="primary", key="analyze_image_payload", use_container_width=True):
                    try:
                        with st.spinner("Checking URL structure and risk indicators..."):
                            st.markdown("<div class='qs-scanline'></div>", unsafe_allow_html=True)
                            result = analyze_payload(preview)
                            save_scan(result, source="QR image / camera")
                            st.session_state.qrshield_latest_result = result
                            st.session_state.qrshield_scan_counter += 1
                        st.success("Analysis complete. Review the findings below.")
                    except ValueError as error:
                        st.error(str(error))
        except ValueError as error:
            st.error(str(error))
        except Exception as error:
            st.error(f"The image could not be analyzed: {error}")

with text_tab:
    st.markdown("<div class='qs-panel'><h3>2. Analyze decoded text or a URL</h3><p class='qs-muted'>Use this when you already know what the QR code contains. Sensitive query values and Wi-Fi passwords are masked in reports and saved history.</p></div>", unsafe_allow_html=True)
    with st.form("payload_analysis_form"):
        payload = st.text_area(
            "QR payload / URL",
            placeholder="Example: https://example.com or paste the decoded QR text here",
            height=130,
            max_chars=10000,
        )
        submitted = st.form_submit_button("Analyze payload", type="primary", use_container_width=True)
    if submitted:
        try:
            result = analyze_payload(payload)
            save_scan(result, source="Manual payload input")
            st.session_state.qrshield_latest_result = result
            st.session_state.qrshield_scan_counter += 1
            st.success("Analysis complete. Review the findings below.")
        except ValueError as error:
            st.error(str(error))

st.divider()
st.subheader("Latest analysis")
if st.session_state.qrshield_latest_result:
    render_analysis(st.session_state.qrshield_latest_result, key_prefix=f"scanner_{st.session_state.qrshield_scan_counter}")
else:
    st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>AWAITING INPUT</div><h3>No payload analyzed yet</h3><p class='qs-muted'>Upload a QR image or paste a payload to see an explainable risk score, indicators, recommendations, and downloadable reports here.</p></div>", unsafe_allow_html=True)
