#!/usr/bin/env python3
"""
Security Best Practices Generator (Governance Edition) — v2

Generates governance-grade security baselines and runs maturity self-assessments for:
Windows, Linux, web servers, public cloud and Active Directory.

Every control has a stable ID, a priority (P1/P2/P3), an accountable owner and
framework references (ISO/IEC 27001:2022 Annex A, CIS Controls v8, NIST CSF 2.0).

Examples:
    python best_practices_generator.py --target windows --format text
    python best_practices_generator.py --target linux --format markdown --output linux_baseline.md
    python best_practices_generator.py --target all --priority-min P1 --format csv --output p1_controls.csv
    python best_practices_generator.py --target cloud --format html --org "ACME" --output cloud_baseline.html
    python best_practices_generator.py --target active_directory --template --output ad_answers.json
    python best_practices_generator.py --assess ad_answers.json --format markdown --output ad_assessment.md
    python best_practices_generator.py --assess ad_answers.json --fail-under 70   # CI gate
"""

import argparse
import csv
import html
import io
import json
import sys
from collections import OrderedDict, defaultdict
from datetime import date
from typing import Dict, Iterable, List, Optional

from controls_catalog import BEST_PRACTICES, DOMAIN_METADATA, ISO27001_TITLES, NIST_CSF_FUNCTIONS, TARGET_LABELS

__version__ = "2.0.0"

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3}
PRIORITY_WEIGHT = {"P1": 3, "P2": 2, "P3": 1}
STATUS_CREDIT = {"implemented": 1.0, "partial": 0.5, "not_implemented": 0.0}
VALID_STATUSES = ["implemented", "partial", "not_implemented", "not_applicable"]
ROADMAP_HORIZON = {"P1": "0-30 days", "P2": "31-90 days", "P3": "91-180 days"}
MATURITY_LEVELS = [(90, "5 - Optimized"), (80, "4 - Managed"), (60, "3 - Defined"), (40, "2 - Developing"), (0, "1 - Initial")]


# --------------------------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------------------------

def priority_code(priority: str) -> str:
    return priority.split()[0]


def select_controls(targets: Iterable[str], priority_min: str = "P3", domains: Optional[List[str]] = None) -> List[Dict]:
    """Flatten the catalogue into rows, applying priority and domain filters."""
    max_rank = PRIORITY_RANK[priority_min]
    needles = [d.lower() for d in domains or []]
    rows: List[Dict] = []
    for target in targets:
        for domain, controls in BEST_PRACTICES[target].items():
            if needles and not any(n in domain.lower() for n in needles):
                continue
            meta = DOMAIN_METADATA[domain]
            for ctrl in controls:
                code = priority_code(ctrl["priority"])
                if PRIORITY_RANK[code] > max_rank:
                    continue
                rows.append({
                    "target": target,
                    "domain": domain,
                    "id": ctrl["id"],
                    "priority": ctrl["priority"],
                    "priority_code": code,
                    "description": ctrl["description"],
                    "owner": meta["owner"],
                    "iso27001": meta["iso27001"],
                    "cis_v8": meta["cis_v8"],
                    "nist_csf": meta["nist_csf"],
                })
    return rows


def group_pairs(rows: List[Dict]) -> "OrderedDict":
    """Group rows by (target, domain) while preserving catalogue order."""
    grouped: "OrderedDict" = OrderedDict()
    for row in rows:
        grouped.setdefault((row["target"], row["domain"]), []).append(row)
    return grouped


def _refs(row: Dict) -> str:
    return (f"ISO 27001 {', '.join(row['iso27001'])} | CIS v8 {', '.join(row['cis_v8'])} | "
            f"NIST CSF {', '.join(row['nist_csf'])}")


def _title(targets: List[str]) -> str:
    if len(targets) > 2:
        return "Security Baseline – Multi-platform"
    return "Security Baseline – " + ", ".join(TARGET_LABELS[t] for t in targets)


def _priority_summary(rows: List[Dict]) -> str:
    counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        counts[row["priority_code"]] += 1
    return ", ".join(f"{p}: {counts[p]}" for p in ("P1", "P2", "P3"))


# --------------------------------------------------------------------------------------------
# Baseline renderers
# --------------------------------------------------------------------------------------------

def render_text(rows: List[Dict], targets: List[str], org: str = "") -> str:
    title = _title(targets) + (f" ({org})" if org else "")
    lines = [title, "=" * len(title), ""]
    current_target = None
    for (target, domain), controls in group_pairs(rows).items():
        if len(targets) > 1 and target != current_target:
            lines += [f"[{TARGET_LABELS[target]}]", ""]
            current_target = target
        lines += [domain, "-" * len(domain), f"Owner: {controls[0]['owner']} | {_refs(controls[0])}"]
        for idx, ctrl in enumerate(controls, start=1):
            lines.append(f"{idx}. {ctrl['id']} [{ctrl['priority']}] {ctrl['description']}")
        lines.append("")
    return "\n".join(lines)


def render_markdown(rows: List[Dict], targets: List[str], org: str = "", checklist: bool = False) -> str:
    lines = [f"# {_title(targets)}", "",
             f"**Organization:** {org or 'n/a'}  ",
             f"**Generated:** {date.today().isoformat()} — Security Best Practices Generator v{__version__}  ",
             f"**Controls:** {len(rows)} ({_priority_summary(rows)})", ""]
    if not checklist:
        lines += ["> Priorities: **P1** = must-have baseline, **P2** = short-term, **P3** = improvement. "
                  "Framework references are indicative (domain level).", ""]
    current_target = None
    for section, ((target, domain), controls) in enumerate(group_pairs(rows).items(), start=1):
        if len(targets) > 1 and target != current_target:
            lines += [f"# {TARGET_LABELS[target]}", ""]
            current_target = target
        lines += [f"## {section}. {domain}", "", f"*Owner: {controls[0]['owner']} — {_refs(controls[0])}*", ""]
        for idx, ctrl in enumerate(controls, start=1):
            if checklist:
                lines.append(f"- [ ] **{ctrl['id']}** `{ctrl['priority_code']}` {ctrl['description']}")
            else:
                lines.append(f"{idx}. **{ctrl['id']}** `[{ctrl['priority']}]` {ctrl['description']}")
        lines.append("")
    return "\n".join(lines)


def render_json(rows: List[Dict], targets: List[str], org: str = "") -> str:
    return json.dumps({"generator": f"sbpg {__version__}", "organization": org, "generated": date.today().isoformat(),
                       "targets": targets, "count": len(rows), "controls": rows}, indent=2, ensure_ascii=False)


def render_csv(rows: List[Dict], targets: List[str], org: str = "") -> str:
    buffer = io.StringIO()
    fields = ["target", "domain", "id", "priority_code", "description", "owner", "iso27001", "cis_v8", "nist_csf"]
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "iso27001": " ".join(row["iso27001"]), "cis_v8": " ".join(row["cis_v8"]),
                         "nist_csf": " ".join(row["nist_csf"])})
    return buffer.getvalue()


HTML_STYLE = """
:root{--bg:#f6f8fb;--panel:#fff;--text:#111a2b;--muted:#5c6880;--line:#dde3ee;--p1:#c62839;--p2:#a86a00;--p3:#2a5bd7;--ok:#13865a}
@media (prefers-color-scheme:dark){:root{--bg:#0d1220;--panel:#151c2e;--text:#eaf0fb;--muted:#9aa6bf;--line:#28324a;--p1:#ff8d9a;--p2:#ffd27a;--p3:#8fb3ff;--ok:#7ce0b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:40px 22px}h1{margin:0 0 6px;font-size:2rem}h2{margin:30px 0 4px;font-size:1.2rem}
.meta{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}.card b{display:block;font-size:1.6rem}
.refs{color:var(--muted);font-size:.85rem;margin-bottom:8px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.p{font-weight:800;white-space:nowrap}.P1{color:var(--p1)}.P2{color:var(--p2)}.P3{color:var(--p3)}code{font-size:.85rem}
progress{width:100%;height:9px;accent-color:var(--ok)}
footer{margin-top:30px;color:var(--muted);font-size:.8rem}
"""


def _html_page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            f"content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title><style>{HTML_STYLE}</style>"
            f"</head><body><main>{body}<footer>Generated {date.today().isoformat()} by Security Best Practices Generator "
            f"v{__version__}. Framework references are indicative.</footer></main></body></html>")


def render_html(rows: List[Dict], targets: List[str], org: str = "") -> str:
    counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        counts[row["priority_code"]] += 1
    parts = [f"<h1>{html.escape(_title(targets))}</h1><p class=\"meta\">Organization: {html.escape(org or 'n/a')}</p>",
             "<div class=\"cards\">", f"<div class=\"card\">Controls<b>{len(rows)}</b></div>",
             *[f"<div class=\"card\">{p}<b class=\"{p}\">{counts[p]}</b></div>" for p in ("P1", "P2", "P3")], "</div>"]
    for (target, domain), controls in group_pairs(rows).items():
        label = f"{TARGET_LABELS[target]} — {domain}" if len(targets) > 1 else domain
        parts.append(f"<h2>{html.escape(label)}</h2><div class=\"refs\">Owner: {html.escape(controls[0]['owner'])} · "
                     f"{html.escape(_refs(controls[0]))}</div>")
        parts.append("<table><thead><tr><th>ID</th><th>Priority</th><th>Control</th></tr></thead><tbody>")
        for c in controls:
            parts.append(f"<tr><td><code>{c['id']}</code></td><td class=\"p {c['priority_code']}\">{c['priority_code']}</td>"
                         f"<td>{html.escape(c['description'])}</td></tr>")
        parts.append("</tbody></table>")
    return _html_page(_title(targets), "".join(parts))


# --------------------------------------------------------------------------------------------
# Self-assessment
# --------------------------------------------------------------------------------------------

def build_template(rows: List[Dict], targets: List[str], org: str = "") -> str:
    return json.dumps({
        "organization": org or "Your organization",
        "targets": targets,
        "assessed_by": "",
        "date": date.today().isoformat(),
        "instructions": f"Set each control to one of: {', '.join(VALID_STATUSES)}. Optional: add a note in 'notes'.",
        "answers": {row["id"]: "not_implemented" for row in rows},
        "notes": {},
    }, indent=2)


def maturity_label(score: float) -> str:
    return next(label for threshold, label in MATURITY_LEVELS if score >= threshold)


def _score(items: List[Dict]) -> Optional[float]:
    scorable = [i for i in items if i["status"] != "not_applicable"]
    weight = sum(PRIORITY_WEIGHT[i["priority_code"]] for i in scorable)
    if not weight:
        return None
    earned = sum(PRIORITY_WEIGHT[i["priority_code"]] * STATUS_CREDIT[i["status"]] for i in scorable)
    return round(100 * earned / weight, 1)


def assess(answers_doc: Dict) -> Dict:
    """Score answers against the catalogue: weighted by priority, partial = half credit."""
    targets = answers_doc.get("targets") or [answers_doc.get("target")]
    unknown_targets = [t for t in targets if t not in BEST_PRACTICES]
    if unknown_targets:
        raise ValueError(f"Unknown target(s): {unknown_targets}")
    answers: Dict[str, str] = answers_doc.get("answers", {})
    notes: Dict[str, str] = answers_doc.get("notes", {})
    invalid = {k: v for k, v in answers.items() if v not in VALID_STATUSES}
    if invalid:
        raise ValueError(f"Invalid status values: {invalid}. Allowed: {VALID_STATUSES}")

    items = [{**row, "status": answers.get(row["id"], "not_implemented"), "note": notes.get(row["id"], ""),
              "answered": row["id"] in answers} for row in select_controls(targets)]

    domains = []
    for (target, domain), group in group_pairs(items).items():
        score = _score(group)
        domains.append({"target": target, "domain": domain, "owner": group[0]["owner"], "score": score,
                        "maturity": maturity_label(score) if score is not None else "n/a",
                        "gaps": sum(1 for g in group if g["status"] in {"not_implemented", "partial"})})

    by_function: Dict[str, List[Dict]] = defaultdict(list)
    by_iso: Dict[str, List[Dict]] = defaultdict(list)
    for item in items:
        for fn in item["nist_csf"]:
            by_function[fn].append(item)
        for ref in item["iso27001"]:
            by_iso[ref].append(item)
    nist = [{"function": f"{code} - {NIST_CSF_FUNCTIONS[code]}", "score": _score(by_function[code])}
            for code in NIST_CSF_FUNCTIONS if code in by_function]
    iso = sorted([{"control": ref, "title": ISO27001_TITLES.get(ref, ""), "score": _score(group)}
                  for ref, group in by_iso.items()],
                 key=lambda r: (r["score"] if r["score"] is not None else 101, r["control"]))

    gaps = sorted([i for i in items if i["status"] in {"not_implemented", "partial"}],
                  key=lambda i: (PRIORITY_RANK[i["priority_code"]], i["status"] != "not_implemented", i["id"]))
    keep = ("id", "target", "domain", "priority_code", "status", "description", "owner")
    roadmap = OrderedDict((ROADMAP_HORIZON[p], [{k: g[k] for k in keep} for g in gaps if g["priority_code"] == p])
                          for p in ("P1", "P2", "P3"))
    overall = _score(items) or 0.0

    return {
        "organization": answers_doc.get("organization", ""),
        "assessed_by": answers_doc.get("assessed_by", ""),
        "date": answers_doc.get("date", date.today().isoformat()),
        "targets": targets,
        "overall_score": overall,
        "maturity": maturity_label(overall),
        "controls": len(items),
        "unanswered": sum(1 for i in items if not i["answered"]),
        "status_counts": {s: sum(1 for i in items if i["status"] == s) for s in VALID_STATUSES},
        "critical_gaps": sum(1 for g in gaps if g["priority_code"] == "P1" and g["status"] == "not_implemented"),
        "domains": sorted(domains, key=lambda d: (d["score"] if d["score"] is not None else 101)),
        "nist_csf": nist,
        "iso27001": iso,
        "roadmap": roadmap,
    }


def _fmt(score: Optional[float]) -> str:
    return "n/a" if score is None else f"{score:.0f}%"


def render_assessment_markdown(result: Dict) -> str:
    lines = [f"# Security Maturity Assessment — {result['organization'] or 'Organization'}", "",
             f"**Scope:** {', '.join(TARGET_LABELS[t] for t in result['targets'])}  ",
             f"**Date:** {result['date']}  "]
    if result["assessed_by"]:
        lines.append(f"**Assessed by:** {result['assessed_by']}  ")
    lines += ["", "## 1. Executive summary", "",
              f"- **Overall score:** {result['overall_score']:.0f}% — maturity **{result['maturity']}**",
              f"- **Critical gaps (P1 not implemented):** {result['critical_gaps']}",
              "- **Status:** " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in result["status_counts"].items())]
    if result["unanswered"]:
        lines.append(f"- ⚠️ {result['unanswered']} unanswered control(s) were scored as *not implemented*.")
    weakest = [d for d in result["domains"] if d["score"] is not None][:3]
    if weakest:
        lines.append("- **Weakest domains:** " + ", ".join(f"{d['domain']} ({_fmt(d['score'])})" for d in weakest))
    lines += ["", "## 2. Maturity by domain", "", "| Domain | Owner | Score | Maturity | Gaps |", "|---|---|---:|---|---:|"]
    for d in result["domains"]:
        label = d["domain"] if len(result["targets"]) == 1 else f"{TARGET_LABELS[d['target']]} — {d['domain']}"
        lines.append(f"| {label} | {d['owner']} | {_fmt(d['score'])} | {d['maturity']} | {d['gaps']} |")
    lines += ["", "## 3. NIST CSF 2.0 view", "", "| Function | Score |", "|---|---:|"]
    lines += [f"| {n['function']} | {_fmt(n['score'])} |" for n in result["nist_csf"]]
    lines += ["", "## 4. ISO/IEC 27001:2022 Annex A — weakest controls", "", "| Control | Title | Score |", "|---|---|---:|"]
    lines += [f"| {r['control']} | {r['title']} | {_fmt(r['score'])} |" for r in result["iso27001"][:8]]
    lines += ["", "## 5. Remediation roadmap", ""]
    for horizon, items in result["roadmap"].items():
        lines += [f"### {horizon} ({len(items)})", ""]
        if not items:
            lines += ["_No gap._", ""]
            continue
        for g in items:
            flag = " *(partial)*" if g["status"] == "partial" else ""
            lines.append(f"- [ ] **{g['id']}** — {g['description']}{flag} — _owner: {g['owner']}_")
        lines.append("")
    lines += ["---", "_Score = priority-weighted coverage (P1×3, P2×2, P3×1; partial = 50%). "
              "Indicative self-assessment, not an audit opinion._", ""]
    return "\n".join(lines)


def render_assessment_text(result: Dict) -> str:
    lines = [f"Security maturity: {result['overall_score']:.0f}% ({result['maturity']}) — "
             f"{result['critical_gaps']} critical gap(s)", ""]
    lines += [f"  {_fmt(d['score']):>5}  {d['domain']}  [{d['maturity']}]" for d in result["domains"]]
    first = result["roadmap"][ROADMAP_HORIZON["P1"]]
    lines += ["", "Next 30 days:"] + ([f"  - {g['id']}: {g['description']}" for g in first] or ["  - none"])
    return "\n".join(lines)


def render_assessment_html(result: Dict) -> str:
    title = f"Security Maturity Assessment — {result['organization'] or 'Organization'}"
    parts = [f"<h1>{html.escape(title)}</h1><p class=\"meta\">{html.escape(result['date'])} · "
             f"{html.escape(', '.join(TARGET_LABELS[t] for t in result['targets']))}</p>",
             "<div class=\"cards\">",
             f"<div class=\"card\">Overall score<b>{result['overall_score']:.0f}%</b>{html.escape(result['maturity'])}</div>",
             f"<div class=\"card\">Critical gaps<b class=\"P1\">{result['critical_gaps']}</b>P1 not implemented</div>",
             f"<div class=\"card\">Implemented<b>{result['status_counts']['implemented']}</b>of {result['controls']}</div>",
             "</div><h2>Maturity by domain</h2><table><thead><tr><th>Domain</th><th>Owner</th><th>Score</th>"
             "<th>Coverage</th></tr></thead><tbody>"]
    for d in result["domains"]:
        value = 0 if d["score"] is None else d["score"]
        parts.append(f"<tr><td>{html.escape(d['domain'])}</td><td>{html.escape(d['owner'])}</td><td>{_fmt(d['score'])}</td>"
                     f"<td><progress max=\"100\" value=\"{value}\"></progress></td></tr>")
    parts.append("</tbody></table><h2>NIST CSF 2.0</h2><table><tbody>")
    parts += [f"<tr><td>{html.escape(n['function'])}</td><td>{_fmt(n['score'])}</td></tr>" for n in result["nist_csf"]]
    parts.append("</tbody></table><h2>Remediation roadmap</h2>")
    for horizon, items in result["roadmap"].items():
        parts.append(f"<h3>{horizon} ({len(items)})</h3><table><tbody>")
        parts += [f"<tr><td><code>{g['id']}</code></td><td class=\"p {g['priority_code']}\">{g['priority_code']}</td>"
                  f"<td>{html.escape(g['description'])}</td><td>{html.escape(g['owner'])}</td></tr>" for g in items]
        parts.append("</tbody></table>")
    return _html_page(title, "".join(parts))


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------

BASELINE_RENDERERS = {
    "text": render_text,
    "markdown": render_markdown,
    "checklist": lambda rows, targets, org="": render_markdown(rows, targets, org, checklist=True),
    "json": render_json,
    "csv": render_csv,
    "html": render_html,
}
ASSESSMENT_RENDERERS = {
    "text": render_assessment_text,
    "markdown": render_assessment_markdown,
    "json": lambda result: json.dumps(result, indent=2, ensure_ascii=False),
    "html": render_assessment_html,
}


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate governance-grade security baselines and run maturity self-assessments.")
    parser.add_argument("--target", choices=[*BEST_PRACTICES.keys(), "all"],
                        help="windows, linux, webserver, cloud, active_directory or all.")
    parser.add_argument("--format", choices=sorted(BASELINE_RENDERERS), default="text", help="Output format (default: text).")
    parser.add_argument("--priority-min", choices=["P1", "P2", "P3"], default="P3",
                        help="Lowest priority to include: P1 = critical only, P2 = P1+P2, P3 = all (default).")
    parser.add_argument("--domain", action="append", help="Keep only domains containing this text (repeatable).")
    parser.add_argument("--org", default="", help="Organization name shown in reports.")
    parser.add_argument("--output", help="Write to this file instead of stdout.")
    parser.add_argument("--list-targets", action="store_true", help="List targets and control counts.")
    parser.add_argument("--stats", action="store_true", help="Show catalogue statistics by target and priority.")
    parser.add_argument("--template", action="store_true", help="Generate a JSON answers template for --assess.")
    parser.add_argument("--assess", metavar="ANSWERS.json", help="Score a completed answers file.")
    parser.add_argument("--fail-under", type=float, metavar="SCORE",
                        help="With --assess: exit with code 2 if the overall score is below SCORE (CI gate).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if not (args.target or args.assess or args.list_targets or args.stats):
        parser.error("--target is required (or use --assess, --list-targets, --stats)")
    return args


def _write(content: str, output: Optional[str], label: str) -> None:
    if output:
        with open(output, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        print(f"[+] {label} written to {output}", file=sys.stderr)
    else:
        print(content)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_arguments(argv)

    if args.list_targets or args.stats:
        lines = []
        for target, domains in BEST_PRACTICES.items():
            rows = select_controls([target])
            line = f"{target:<18} {TARGET_LABELS[target]:<36} {len(rows):>3} controls, {len(domains)} domains"
            lines.append(line + (f"  ({_priority_summary(rows)})" if args.stats else ""))
        if args.stats:
            lines.append(f"{'TOTAL':<18} {'':<36} {len(select_controls(BEST_PRACTICES)):>3} controls")
        print("\n".join(lines))
        return 0

    if args.assess:
        try:
            with open(args.assess, encoding="utf-8") as handle:
                result = assess(json.load(handle))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"[!] Cannot assess {args.assess}: {exc}", file=sys.stderr)
            return 1
        fmt = args.format if args.format in ASSESSMENT_RENDERERS else "markdown"
        _write(ASSESSMENT_RENDERERS[fmt](result), args.output, "Assessment")
        if args.fail_under is not None and result["overall_score"] < args.fail_under:
            print(f"[!] Score {result['overall_score']}% is below the required {args.fail_under}%", file=sys.stderr)
            return 2
        return 0

    targets = list(BEST_PRACTICES) if args.target == "all" else [args.target]
    rows = select_controls(targets, args.priority_min, args.domain)
    if not rows:
        print("[!] No control matches the selected filters.", file=sys.stderr)
        return 1
    if args.template:
        _write(build_template(rows, targets, args.org), args.output, "Assessment template")
        return 0
    _write(BASELINE_RENDERERS[args.format](rows, targets, args.org), args.output, "Baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
