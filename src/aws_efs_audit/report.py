"""Renderers: text for humans, json for pipelines, markdown for pull requests."""

from __future__ import annotations

import json
from typing import Any

from .model import SEVERITIES, FileSystemReport, worst

MARK = {"critical": "CRIT", "warn": "WARN", "info": "INFO", "ok": "OK"}


def summarise(reports: list[FileSystemReport]) -> dict[str, Any]:
    by_fs = {sev: 0 for sev in SEVERITIES}
    by_finding = {sev: 0 for sev in SEVERITIES}
    for r in reports:
        by_fs[r.severity] += 1
        for f in r.findings:
            by_finding[f.severity] += 1
    return {
        "file_systems": len(reports),
        "findings": sum(len(r.findings) for r in reports),
        "by_severity": by_fs,
        "findings_by_severity": by_finding,
        "worst_severity": worst(r.severity for r in reports),
        "monthly_saving_usd": round(sum(r.monthly_saving_usd for r in reports), 2),
    }


def _ordered(reports: list[FileSystemReport]) -> list[FileSystemReport]:
    rank = {"critical": 0, "warn": 1, "info": 2, "ok": 3}
    return sorted(reports, key=lambda r: (rank[r.severity], r.region, r.file_system_id))


def render_text(reports: list[FileSystemReport]) -> str:
    lines: list[str] = []
    for r in _ordered(reports):
        head = f"{r.region}  {r.file_system_id}"
        if r.name:
            head += f"  ({r.name})"
        head += f"  {r.size_gb:,.0f} GB total / {r.standard_gb:,.0f} GB Standard  [{MARK[r.severity]}]"
        lines.append(head)
        if not r.findings:
            lines.append("    nothing to fix")
        for f in r.findings:
            lines.append(f"    {MARK[f.severity]:<4} {f.title}")
            lines.append(f"         {f.detail}")
            lines.append(f"         fix: {f.fix}")
        lines.append("")
    s = summarise(reports)
    lines.append(
        f"{s['file_systems']} file system(s): {s['by_severity']['critical']} critical, "
        f"{s['by_severity']['warn']} warn, {s['by_severity']['ok']} clean"
    )
    lines.append(
        f"{s['findings']} finding(s): {s['findings_by_severity']['critical']} critical, "
        f"{s['findings_by_severity']['warn']} warn"
    )
    if s["monthly_saving_usd"]:
        lines.append(f"estimated monthly saving if fixed: ${s['monthly_saving_usd']:,.2f}")
    return "\n".join(lines)


def render_markdown(reports: list[FileSystemReport]) -> str:
    s = summarise(reports)
    out = ["# EFS audit", ""]
    out.append(
        f"{s['file_systems']} file system(s): **{s['by_severity']['critical']} critical**, "
        f"{s['by_severity']['warn']} warn, {s['by_severity']['ok']} clean. "
        f"{s['findings']} finding(s) in total."
    )
    if s["monthly_saving_usd"]:
        out.append("")
        out.append(f"Estimated monthly saving if fixed: **${s['monthly_saving_usd']:,.2f}**.")
    out.append("")
    out.append("| Region | File system | Standard GB | Severity | Findings |")
    out.append("| --- | --- | --- | --- | --- |")
    for r in _ordered(reports):
        label = r.file_system_id + (f" ({r.name})" if r.name else "")
        rules = ", ".join(f.rule for f in r.findings) or "-"
        out.append(
            f"| {r.region} | {label} | {r.standard_gb:,.0f} | {r.severity} | {rules} |"
        )
    for r in _ordered(reports):
        if not r.findings:
            continue
        out.append("")
        out.append(f"## {r.region} / {r.file_system_id}")
        for f in r.findings:
            out.append("")
            out.append(f"- **{f.severity}: {f.title}** - {f.detail}.")
            out.append(f"  Fix: {f.fix}.")
    return "\n".join(out) + "\n"


def render_json(reports: list[FileSystemReport]) -> str:
    return json.dumps(
        {
            "summary": summarise(reports),
            "filesystems": [r.to_dict() for r in reports],
        },
        indent=2,
        sort_keys=False,
    )


def render(reports: list[FileSystemReport], fmt: str) -> str:
    if fmt == "json":
        return render_json(reports)
    if fmt == "markdown":
        return render_markdown(reports)
    return render_text(reports)
