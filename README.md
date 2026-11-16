# 🔐 Security Best Practices Generator — Governance Edition v2

**Generate governance-grade security baselines and run maturity self-assessments, mapped to ISO/IEC 27001:2022, CIS Controls v8 and NIST CSF 2.0.**

Built from a CISO / CIO perspective: a baseline is only useful if every control has an ID, a priority, an owner and a framework reference — and if you can measure how far you are from it.

## ✨ What's new in v2

| Area | v1 | v2 |
|---|---|---|
| Targets | Windows, Linux, web server | + **Public cloud** and **Active Directory** |
| Controls | 95 | **145** |
| Framework mapping | — | ISO 27001:2022 Annex A, CIS Controls v8, NIST CSF 2.0, accountable owner |
| Formats | text, markdown | + **json, csv, html, checklist** |
| Filters | — | `--priority-min`, `--domain`, `--target all` |
| Assessment | — | **Maturity self-assessment**: weighted score, maturity level, NIST/ISO views, 30/90/180-day roadmap |
| Automation | — | `--fail-under` exit code for CI/CD gates, pytest suite, GitHub Actions |

## Targets

| Target | Scope | Controls |
|---|---|---:|
| `windows` | Workstations & servers | 30 |
| `linux` | Servers & desktops | 30 |
| `webserver` | Web servers & web applications | 35 |
| `cloud` | AWS / Azure / GCP — IAM, exposure, logging, data, governance | 25 |
| `active_directory` | Tiering, credential protection, Kerberos, hygiene, forest recovery | 25 |

Priorities: **P1 – Critical** (must-have baseline), **P2 – High** (short term), **P3 – Medium** (improvement).

## Quick start

Python 3.9+, no external dependency.

```bash
python best_practices_generator.py --list-targets
python best_practices_generator.py --stats

# Baselines
python best_practices_generator.py --target windows --format text
python best_practices_generator.py --target cloud --format html --org "ACME" --output cloud_baseline.html
python best_practices_generator.py --target all --priority-min P1 --format csv --output p1_controls.csv
python best_practices_generator.py --target webserver --domain tls --domain headers --format markdown
python best_practices_generator.py --target active_directory --format checklist --output ad_checklist.md
```

## Maturity self-assessment

```bash
# 1. Generate an answers template
python best_practices_generator.py --target active_directory --template --org "ACME" --output ad_answers.json

# 2. Set each control to implemented | partial | not_implemented | not_applicable

# 3. Produce the assessment report (markdown, html, json or text)
python best_practices_generator.py --assess ad_answers.json --format markdown --output ad_assessment.md

# 4. Optional CI/CD gate: exit code 2 below the threshold
python best_practices_generator.py --assess ad_answers.json --fail-under 70
```

Scoring is explainable: priority-weighted coverage (P1 ×3, P2 ×2, P3 ×1; partial = 50%; not applicable excluded).

| Score | Maturity |
|---|---|
| ≥ 90% | 5 – Optimized |
| ≥ 80% | 4 – Managed |
| ≥ 60% | 3 – Defined |
| ≥ 40% | 2 – Developing |
| < 40% | 1 – Initial |

The report contains an executive summary, maturity by domain with owners, a NIST CSF 2.0 view, the weakest ISO 27001 Annex A controls and a remediation roadmap (P1 → 0-30 days, P2 → 31-90 days, P3 → 91-180 days).

## Examples

See [`examples/`](examples/): a Windows baseline (Markdown), a cloud baseline (HTML), all P1 controls (CSV), an AD checklist and a complete **Active Directory assessment** of a fictional company (score 53%, maturity "Developing", 3 critical gaps).

## Project structure

```text
best_practices_generator.py   CLI, renderers and assessment engine
controls_catalog.py           145 controls + domain-level framework metadata
examples/                     generated outputs and sample answers
tests/                        pytest suite (catalogue integrity, formats, scoring, CLI)
.github/workflows/ci.yml      tests on Python 3.9 and 3.12
```

## Run tests

```bash
pip install pytest
python -m pytest -q
```

## Disclaimer

Framework references are indicative and maintained at domain level. The tool supports self-assessment and planning; it is not an audit or certification opinion. Always adapt baselines to your context and to vendor guidance (CIS Benchmarks, ANSSI, Microsoft, cloud providers).

## License

MIT
