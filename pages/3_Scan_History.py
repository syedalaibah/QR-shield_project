from __future__ import annotations

import pandas as pd
import streamlit as st

from qrshield.database import clear_scans, get_scan, get_scans
from qrshield.reporting import build_html_report, build_json_report
from qrshield.ui import apply_style, hero, render_analysis

apply_style("Scan History")
hero(
    "Scan History & Investigation Archive",
    "Review previous checks, filter by risk category, inspect the evidence again, and export a report. History is stored in a local SQLite database within the project folder.",
    chips=["LOCAL SQLITE", "FILTERABLE RECORDS", "REVISIT FINDINGS"],
)

rows = get_scans(limit=5000)
if not rows:
    st.info("No saved scans yet. Run an analysis in QR Scanner or Security Lab first.")
    st.page_link("pages/1_QR_Scanner.py", label="Go to QR Scanner →", icon="🔎")
else:
    filters_col, search_col = st.columns([1, 1.6])
    with filters_col:
        levels = st.multiselect("Filter by risk category", ["Low", "Moderate", "High", "Critical"], default=["Low", "Moderate", "High", "Critical"])
    with search_col:
        search = st.text_input("Search payload, type, or source", placeholder="e.g. bit.ly, Web URL, Security Lab")

    filtered = [row for row in rows if row["level"] in levels]
    if search.strip():
        term = search.strip().lower()
        filtered = [row for row in filtered if term in " ".join([row["payload"], row["kind"], row["source"], row["target"]]).lower()]

    st.subheader(f"Matching records · {len(filtered)}")
    display_rows = [
        {
            "ID": row["id"],
            "Date / time": row["analyzed_at"],
            "Source": row["source"],
            "Type": row["kind"],
            "Risk": row["level"],
            "Score": row["score"],
            "Payload / target": row["target"] or row["payload"],
        }
        for row in filtered
    ]
    st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)

    if filtered:
        ids = [row["id"] for row in filtered]
        chosen_id = st.selectbox("Select a scan record to inspect", ids, format_func=lambda value: f"Scan #{value} — {next((r['level'] for r in filtered if r['id'] == value), '')} risk")
        selected = get_scan(chosen_id)
        if selected:
            st.divider()
            st.subheader(f"Scan #{selected['id']} details")
            reconstructed = {
                "payload": selected["payload"],
                "kind": selected["kind"],
                "score": selected["score"],
                "level": selected["level"],
                "summary": f"Saved result from {selected['source']}.",
                "description": "This record was previously analyzed using QRShield's local rules.",
                "target": selected["target"],
                "indicators": selected["indicators"],
                "recommendations": selected["recommendations"],
                "analyzed_at": selected["analyzed_at"],
                "engine": selected["engine"],
            }
            render_analysis(reconstructed, key_prefix=f"history_{selected['id']}")
            c1, c2 = st.columns(2)
            with c1:
                st.download_button("Export selected record as JSON", data=build_json_report(reconstructed), file_name=f"qrshield_scan_{selected['id']}.json", mime="application/json", use_container_width=True)
            with c2:
                st.download_button("Export selected record as HTML", data=build_html_report(reconstructed), file_name=f"qrshield_scan_{selected['id']}.html", mime="text/html", use_container_width=True)

    st.divider()
    with st.expander("Clear local scan history"):
        st.warning("This permanently deletes scan records from this project's local SQLite database. It does not delete report files you already downloaded.")
        confirm = st.checkbox("I understand that all saved scan history will be deleted.", key="confirm_clear_history")
        if st.button("Delete all scan history", type="primary", disabled=not confirm):
            clear_scans()
            st.success("Scan history cleared.")
            st.rerun()
