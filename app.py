from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from qrshield.database import get_scans, initialize_database
from qrshield.ui import apply_style, hero

apply_style("Command Center")
initialize_database()

hero(
    "See the risk before you scan.",
    "QRShield inspects QR-code payloads with explainable, offline rules. Decode an image, review the evidence, and export an investigation report — without automatically opening the destination.",
    chips=["QR IMAGE DECODING", "URL RISK RULES", "LOCAL SCAN HISTORY", "REPORT EXPORT"],
)

scans = get_scans(limit=5000)
count = len(scans)
high_count = sum(1 for row in scans if row["level"] in {"High", "Critical"})
avg_score = round(sum(row["score"] for row in scans) / count, 1) if count else 0
last_scan = scans[0]["analyzed_at"] if scans else "No scans yet"

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total scans", f"{count:,}")
m2.metric("High / critical", f"{high_count:,}")
m3.metric("Average risk score", f"{avg_score}/100")
m4.metric("Latest activity", last_scan.split(" ")[0] if count else "—")

left, right = st.columns([1.3, 1])
with left:
    st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>WORKFLOW</div><h3 style='margin-top:10px'>From QR image to understandable findings</h3><p class='qs-muted'>A clean, explainable workflow designed for a cybersecurity lab demonstration.</p></div>", unsafe_allow_html=True)
    steps = [
        ("01", "Capture the payload", "Upload a PNG/JPG, use your camera, or paste the QR contents."),
        ("02", "Run offline checks", "Inspect URL structure, scheme, hostname, shorteners, and common warning patterns."),
        ("03", "Review the evidence", "Each triggered rule explains its concern and score contribution."),
        ("04", "Export & compare", "Download a report or revisit previous scans stored in local SQLite history."),
    ]
    for number, title, desc in steps:
        st.markdown(
            f"<div style='display:flex;gap:15px;align-items:flex-start;padding:12px 5px;border-bottom:1px solid #24364e'><div style='font-family:monospace;color:#72e6df;font-size:1rem;border:1px solid #35536a;border-radius:10px;padding:8px 10px'>{number}</div><div><div style='font-weight:800'>{title}</div><div class='qs-muted'>{desc}</div></div></div>",
            unsafe_allow_html=True,
        )
with right:
    st.markdown("<div class='qs-panel qs-pulse'><div class='qs-eyebrow'>QUICK START</div><h3 style='margin-top:10px'>Ready to investigate?</h3><p class='qs-muted'>Open QR Scanner from the sidebar. To see the scoring in action first, go to Security Lab and test the bundled, harmless examples.</p></div>", unsafe_allow_html=True)
    st.page_link("pages/1_QR_Scanner.py", label="Open QR Scanner →", icon="🔎", use_container_width=True)
    st.page_link("pages/2_Security_Lab.py", label="Open Security Lab →", icon="🧪", use_container_width=True)
    st.page_link("pages/3_Scan_History.py", label="Review Scan History →", icon="🗂️", use_container_width=True)
    st.markdown("<div class='qs-panel'><div class='qs-eyebrow'>PRIVACY BY DESIGN</div><p class='qs-muted' style='margin-bottom:0'>QRShield does not open QR destinations, execute QR payloads, or send your scans to a threat-intelligence API. Scan history is saved locally in the project folder. Common token and password fields are masked in saved records and reports.</p></div>", unsafe_allow_html=True)

st.subheader("Risk profile")
if scans:
    levels = ["Low", "Moderate", "High", "Critical"]
    counts = {level: sum(1 for row in scans if row["level"] == level) for level in levels}
    chart_df = pd.DataFrame({"Risk category": levels, "Scans": [counts[level] for level in levels]})
    c1, c2 = st.columns([1, 1.2])
    with c1:
        fig = px.pie(chart_df, names="Risk category", values="Scans", hole=0.66, title="Scan distribution")
        fig.update_layout(margin=dict(l=10, r=10, t=60, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dce8f7", legend_title_text="")
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        by_day = pd.DataFrame(scans)
        by_day["Date"] = by_day["analyzed_at"].str[:10]
        timeline = by_day.groupby(["Date", "level"], as_index=False).size().rename(columns={"size": "Scans", "level": "Risk category"})
        fig2 = px.bar(timeline, x="Date", y="Scans", color="Risk category", barmode="stack", title="Scans over time")
        fig2.update_layout(margin=dict(l=10, r=10, t=60, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#dce8f7", xaxis_title="Date", yaxis_title="Number of scans", legend_title_text="")
        st.plotly_chart(fig2, use_container_width=True)
else:
    st.markdown("<div class='qs-panel'><h3>No scan history yet</h3><p class='qs-muted'>Run your first QR scan or test a sample in Security Lab. The charts will populate automatically as history grows.</p></div>", unsafe_allow_html=True)

st.caption("Educational use only • The risk score is heuristic, not a verdict • No URL is opened automatically")
