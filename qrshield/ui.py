"""Shared Streamlit styling and reusable UI helpers."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from qrshield.reporting import build_html_report, build_json_report


CUSTOM_CSS = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --qs-bg:#07111f; --qs-panel:#101d30; --qs-border:#273951; --qs-cyan:#72e6df; --qs-purple:#a78bfa; --qs-muted:#9eb0c8; }
.stApp { background: radial-gradient(ellipse at 10% -10%, rgba(46,119,159,.23), transparent 44%), radial-gradient(ellipse at 100% 8%, rgba(126,87,194,.16), transparent 35%), #07111f; color:#eaf1fb; font-family:'Manrope',sans-serif; }
[data-testid="stHeader"] { background:rgba(7,17,31,.78); }
[data-testid="stAppViewContainer"] .main .block-container { max-width:1320px; padding-top:2rem; padding-bottom:3rem; }
[data-testid="stSidebar"] { background:linear-gradient(180deg,#0b1727 0%,#08111e 100%); border-right:1px solid #23334a; }
[data-testid="stSidebar"] * { font-family:'Manrope',sans-serif; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#adbed3; }
[data-testid="stSidebarNav"] { padding-top:1rem; }
[data-testid="stSidebarNav"] a { border-radius:12px; margin:3px 8px; }
[data-testid="stSidebarNav"] a:hover { background:#15253b; }
h1,h2,h3 { letter-spacing:-.035em; color:#f4f8ff; }
p,li { line-height:1.6; }
.qs-eyebrow { color:var(--qs-cyan); font-family:'DM Mono',monospace; letter-spacing:.18em; font-size:.74rem; font-weight:500; text-transform:uppercase; }
.qs-hero { position:relative; overflow:hidden; border:1px solid rgba(114,230,223,.24); border-radius:24px; padding:30px; margin:4px 0 22px; background:linear-gradient(120deg,rgba(16,36,57,.96),rgba(16,23,46,.93) 58%,rgba(46,27,77,.75)); box-shadow:0 20px 60px rgba(0,0,0,.18); }
.qs-hero:after { content:''; pointer-events:none; position:absolute; width:280px;height:280px;right:-70px;top:-145px;border:1px solid rgba(114,230,223,.2);border-radius:50%;box-shadow:0 0 0 22px rgba(114,230,223,.025),0 0 0 46px rgba(114,230,223,.02),0 0 75px rgba(114,230,223,.12); }
.qs-hero h1 { font-size:clamp(2rem,4vw,3.25rem); margin:.3rem 0 .65rem; }
.qs-hero p { color:#adbed3; max-width:760px; margin-bottom:0; }
.qs-chip { display:inline-block; border:1px solid rgba(114,230,223,.35); background:rgba(114,230,223,.08); color:#9af3eb; padding:5px 10px; border-radius:999px; font-size:.76rem; margin:4px 5px 0 0; }
.qs-panel { border:1px solid #273951; background:linear-gradient(145deg,rgba(16,29,48,.93),rgba(11,23,39,.93)); border-radius:18px; padding:19px 20px; margin:0 0 15px; }
.qs-panel h3 { margin-top:0; font-size:1.05rem; }
.qs-muted { color:#9eb0c8; font-size:.9rem; }
.qs-mono { color:#bad0e6; font-family:'DM Mono',monospace; font-size:.88rem; overflow-wrap:anywhere; }
.qs-status { display:inline-block; padding:6px 12px; border-radius:999px; font-weight:800; font-size:.78rem; letter-spacing:.08em; text-transform:uppercase; }
.qs-low { background:rgba(52,211,153,.12); color:#6ee7b7; border:1px solid rgba(52,211,153,.32); }
.qs-moderate { background:rgba(251,191,36,.12); color:#fcd34d; border:1px solid rgba(251,191,36,.32); }
.qs-high { background:rgba(251,146,60,.12); color:#fdba74; border:1px solid rgba(251,146,60,.32); }
.qs-critical { background:rgba(248,113,113,.13); color:#fca5a5; border:1px solid rgba(248,113,113,.32); }
.qs-scanline { height:3px; width:100%; overflow:hidden; background:#172a40; border-radius:99px; margin:12px 0; }
.qs-scanline:after { content:''; display:block; height:100%; width:35%; border-radius:99px; background:linear-gradient(90deg,transparent,#72e6df,transparent); animation:qs-scan 2.2s ease-in-out infinite; }
@keyframes qs-scan { 0%{transform:translateX(-120%)} 100%{transform:translateX(330%)} }
.qs-pulse { animation:qs-pulse 2.7s ease-in-out infinite; }
@keyframes qs-pulse { 0%,100%{box-shadow:0 0 0 0 rgba(114,230,223,.04)} 50%{box-shadow:0 0 30px 0 rgba(114,230,223,.09)} }
div.stButton > button, div.stDownloadButton > button { border-radius:12px; border:1px solid rgba(114,230,223,.45); min-height:2.7rem; font-weight:700; transition:all .18s ease; }
div.stButton > button[kind="primary"] { background:linear-gradient(100deg,#2caeaa,#657ee8); color:#07111f; border:0; }
div.stButton > button:hover,div.stDownloadButton > button:hover { transform:translateY(-1px); border-color:#72e6df; box-shadow:0 8px 22px rgba(0,0,0,.2); }
[data-testid="stMetric"] { background:linear-gradient(145deg,rgba(16,29,48,.95),rgba(11,23,39,.95)); padding:16px 17px; border:1px solid #273951; border-radius:16px; }
[data-testid="stMetricLabel"] { color:#9eb0c8; }
[data-testid="stMetricValue"] { color:#f4f8ff; }
[data-testid="stExpander"] { border:1px solid #273951; border-radius:13px; background:rgba(16,29,48,.52); }
[data-testid="stDataFrame"] { border:1px solid #273951; border-radius:12px; overflow:hidden; }
hr { border-color:#24364e; }
small { color:#9eb0c8; }
</style>
"""


def apply_style(page_title: str = "QRShield") -> None:
    st.set_page_config(page_title=f"{page_title} | QRShield", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.sidebar.markdown(
        """
        <div style="padding:10px 8px 16px;">
          <div style="font-family:'DM Mono',monospace;color:#72e6df;letter-spacing:.17em;font-size:.72rem;">CYBER DEFENSE / LAB 01</div>
          <div style="display:flex;align-items:center;gap:10px;margin-top:9px;">
            <div style="width:42px;height:42px;display:flex;align-items:center;justify-content:center;border:1px solid #397d8b;border-radius:13px;background:linear-gradient(140deg,#173b50,#211b48);font-size:23px;">⌁</div>
            <div><div style="font-size:1.3rem;font-weight:800;color:#f4f8ff;letter-spacing:-.04em;">QR<span style="color:#72e6df;">Shield</span></div><div style="font-size:.72rem;color:#9eb0c8;">QR threat analyzer</div></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("---")
    st.sidebar.caption("Offline-first • Explainable rules • Local history")
    st.sidebar.markdown(
        "<div style='font-size:.72rem;color:#71869f;padding:12px 8px;'>EDUCATIONAL CYBERSECURITY PROJECT<br>URLs are never opened automatically.</div>",
        unsafe_allow_html=True,
    )


def hero(title: str, subtitle: str, eyebrow: str = "QRSHIELD / CYBER DEFENSE", chips: list[str] | None = None) -> None:
    chip_html = "".join(f"<span class='qs-chip'>{chip}</span>" for chip in (chips or []))
    st.markdown(
        f"""<div class="qs-hero"><div class="qs-eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p><div style="margin-top:17px">{chip_html}</div></div>""",
        unsafe_allow_html=True,
    )


def status_class(level: str) -> str:
    return {
        "Low": "qs-low",
        "Moderate": "qs-moderate",
        "High": "qs-high",
        "Critical": "qs-critical",
    }.get(level, "qs-moderate")


def render_analysis(result: dict, key_prefix: str = "result") -> None:
    """Render result details and safe downloadable reports."""
    score_col, level_col, kind_col = st.columns([1, 1, 1.25])
    with score_col:
        st.metric("Risk score", f"{result.get('score', 0)}/100")
    with level_col:
        st.markdown("<div class='qs-muted'>Risk category</div>", unsafe_allow_html=True)
        st.markdown(
            f"<div style='margin-top:10px'><span class='qs-status {status_class(result.get('level','Low'))}'>{result.get('level','Low')}</span></div>",
            unsafe_allow_html=True,
        )
    with kind_col:
        st.markdown("<div class='qs-muted'>Payload type</div>", unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:1.15rem;font-weight:800;margin-top:8px'>{result.get('kind','Unknown')}</div>", unsafe_allow_html=True)

    score = max(0, min(100, int(result.get("score", 0))))
    color = {"Low": "#34d399", "Moderate": "#fbbf24", "High": "#fb923c", "Critical": "#f87171"}.get(result.get("level"), "#72e6df")
    st.markdown(
        f"<div style='height:8px;background:#1a2a40;border-radius:20px;overflow:hidden;margin:5px 0 17px'><div style='width:{score}%;height:100%;background:{color};border-radius:20px;transition:width 1s ease;'></div></div>",
        unsafe_allow_html=True,
    )
    st.markdown(f"<div class='qs-panel'><div class='qs-eyebrow'>ANALYSIS SUMMARY</div><p style='margin-bottom:0'>{result.get('summary','')}</p><p class='qs-muted' style='margin-top:8px;margin-bottom:0'>{result.get('description','')}</p></div>", unsafe_allow_html=True)

    with st.expander("View payload and destination (sensitive values redacted)", expanded=True):
        st.markdown("**Payload**")
        st.code(result.get("payload", ""), language=None)
        st.markdown("**Destination / target**")
        st.code(result.get("target", ""), language=None)
        st.caption(f"Analyzed at {result.get('analyzed_at', 'unknown')} · Engine: {result.get('engine', 'QRShield Offline Rules v1.0')}")

    st.subheader("Detected indicators")
    indicators = result.get("indicators", [])
    if not indicators:
        st.success("No warning indicators were triggered by the current offline rules.")
    else:
        table_rows = [
            {"Indicator": item.get("indicator", ""), "Severity": item.get("severity", ""), "Points": item.get("points", 0), "Why it matters": item.get("detail", "")}
            for item in indicators
        ]
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    st.subheader("Recommended next steps")
    for item in result.get("recommendations", []):
        st.markdown(f"- {item}")

    st.markdown("<div class='qs-muted'>A low score does not prove a website is safe. QRShield does not open URLs or contact external threat-intelligence services.</div>", unsafe_allow_html=True)
    col_a, col_b, _ = st.columns([1.1, 1.1, 2])
    safe_name = f"qrshield_report_{key_prefix}"
    with col_a:
        st.download_button(
            "⬇ Download JSON report",
            data=build_json_report(result),
            file_name=f"{safe_name}.json",
            mime="application/json",
            key=f"{key_prefix}_json_download",
            use_container_width=True,
        )
    with col_b:
        st.download_button(
            "⬇ Download HTML report",
            data=build_html_report(result),
            file_name=f"{safe_name}.html",
            mime="text/html",
            key=f"{key_prefix}_html_download",
            use_container_width=True,
        )
