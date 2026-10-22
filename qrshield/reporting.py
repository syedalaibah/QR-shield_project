"""Safe report-building helpers."""

from __future__ import annotations

import html
import json
from datetime import datetime


def build_json_report(result: dict) -> bytes:
    clean = {
        "project": "QRShield",
        "report_generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "analysis": result,
        "disclaimer": "Offline rule-based findings only. A low risk score does not prove a destination is safe.",
    }
    return json.dumps(clean, indent=2, ensure_ascii=False).encode("utf-8")


def build_html_report(result: dict) -> bytes:
    escape = html.escape
    indicators = result.get("indicators", [])
    if indicators:
        rows = "".join(
            "<tr>"
            f"<td>{escape(str(item.get('indicator', '')))}</td>"
            f"<td>{escape(str(item.get('severity', '')))}</td>"
            f"<td>{int(item.get('points', 0))}</td>"
            f"<td>{escape(str(item.get('detail', '')))}</td>"
            "</tr>"
            for item in indicators
        )
    else:
        rows = '<tr><td colspan="4">No warning indicators were triggered.</td></tr>'

    recs = "".join(f"<li>{escape(str(item))}</li>" for item in result.get("recommendations", []))
    score = max(0, min(100, int(result.get("score", 0))))
    level = escape(str(result.get("level", "Unknown")))
    content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>QRShield Analysis Report</title>
<style>
:root{{color-scheme:dark}}body{{font-family:Segoe UI,Arial,sans-serif;background:#07111f;color:#e7eef9;margin:0;padding:32px}}
main{{max-width:1000px;margin:auto}}.brand{{color:#72e6df;letter-spacing:.16em;font-size:12px;font-weight:700}}
h1{{margin:.4em 0}}.panel{{background:#101d30;border:1px solid #263752;border-radius:16px;padding:22px;margin:18px 0}}
.score{{font-size:42px;font-weight:800;color:#72e6df}}.muted{{color:#aab9ce}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:12px;border-bottom:1px solid #263752;text-align:left;vertical-align:top}}th{{color:#72e6df}}
code,pre{{white-space:pre-wrap;overflow-wrap:anywhere}}li{{margin:8px 0}}.disclaimer{{font-size:12px;color:#aab9ce}}
@media print{{body{{background:white;color:#111;padding:12px}}.panel{{background:white;color:#111;border:1px solid #ddd}}th{{color:#111}}.muted,.disclaimer{{color:#333}}}}
</style></head><body><main>
<div class="brand">QRSHIELD / SECURITY ANALYSIS</div><h1>QR Payload Risk Report</h1>
<p class="muted">Generated: {escape(datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z'))}</p>
<section class="panel"><div class="score">{score}/100 · {level}</div><h2>{escape(str(result.get('kind','Unknown')))}</h2>
<p>{escape(str(result.get('summary','')))}</p><p><b>Analyzed:</b> {escape(str(result.get('analyzed_at','')))}</p>
<p><b>Payload (sensitive values redacted):</b></p><pre>{escape(str(result.get('payload','')))}</pre>
<p><b>Destination / target:</b></p><pre>{escape(str(result.get('target','')))}</pre></section>
<section class="panel"><h2>Indicators</h2><table><thead><tr><th>Indicator</th><th>Severity</th><th>Points</th><th>Explanation</th></tr></thead><tbody>{rows}</tbody></table></section>
<section class="panel"><h2>Recommended next steps</h2><ul>{recs}</ul></section>
<section class="panel"><h2>Method and limitations</h2><p>{escape(str(result.get('description','')))}</p>
<p class="disclaimer">{escape(str(result.get('engine','QRShield Offline Rules v1.0')))}. This report is generated using local heuristics. QRShield does not visit URLs, query external threat-intelligence services, or guarantee that any destination is safe or malicious.</p></section>
</main></body></html>"""
    return content.encode("utf-8")
