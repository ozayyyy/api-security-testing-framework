"""Reporting: JSON, Markdown and HTML exports. All output is redacted
at evidence-creation time; the exporters only format it.
"""
from __future__ import annotations

import html
import json

from apistf.findings import Finding


def to_json(findings: list[Finding]) -> str:
    return json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2)


def to_markdown(findings: list[Finding]) -> str:
    lines = ["# API Security Findings", ""]
    lines.append(f"Total findings: {len(findings)}")
    confirmed = sum(1 for f in findings if f.status.value == "confirmed")
    lines.append(f"Confirmed: {confirmed} | Suspected: "
                 f"{sum(1 for f in findings if f.status.value == 'suspected')} | "
                 f"Informational: {sum(1 for f in findings if f.status.value == 'informational')}")
    lines.append("")
    for f in findings:
        lines.append(f"## {f.title}")
        lines.append("")
        lines.append(f"- Detector: `{f.detector}`")
        lines.append(f"- Severity: {f.severity.value} | Status: {f.status.value} | Confidence: {f.confidence}")
        lines.append(f"- Endpoint: `{f.endpoint}`")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.reproduction:
            lines.append("### Reproduction")
            lines.append("")
            for step in f.reproduction:
                lines.append(f"- {step}")
            lines.append("")
        for ev in f.evidence:
            lines.append(f"### Evidence: {ev.method} {ev.url} -> {ev.response_status}")
            lines.append("")
            lines.append("```")
            lines.append(f"Request headers: {ev.request_headers}")
            if ev.request_body:
                lines.append(f"Request body: {ev.request_body}")
            lines.append(f"Response body: {ev.response_body[:2000]}")
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def to_html(findings: list[Finding]) -> str:
    rows = ""
    for f in findings:
        ev_html = "".join(
            f"<li><code>{html.escape(e.method)} {html.escape(e.url)} &rarr; {e.response_status}</code>"
            f"<pre>{html.escape(e.response_body[:2000])}</pre></li>"
            for e in f.evidence
        )
        rows += (
            f"<section><h2>{html.escape(f.title)}</h2>"
            f"<p>Detector: <code>{html.escape(f.detector)}</code> | "
            f"Severity: {f.severity.value} | Status: {f.status.value} | "
            f"Confidence: {html.escape(f.confidence)}</p>"
            f"<p>{html.escape(f.description)}</p>"
            f"<p>Endpoint: <code>{html.escape(f.endpoint)}</code></p>"
            f"<ul>{ev_html}</ul></section>"
        )
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        "<title>API Security Findings</title></head><body>"
        f"<h1>API Security Findings ({len(findings)})</h1>{rows}</body></html>"
    )


def write_report(findings: list[Finding], path: str, fmt: str) -> None:
    fmt = fmt.lower()
    text = {"json": to_json, "md": to_markdown, "markdown": to_markdown,
            "html": to_html}[fmt](findings)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
