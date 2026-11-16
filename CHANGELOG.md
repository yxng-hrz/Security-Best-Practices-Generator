# Changelog

## 2.0.0
- New targets: `cloud` (25 controls) and `active_directory` (25 controls) — 145 controls in total.
- Domain-level mapping to ISO/IEC 27001:2022 Annex A, CIS Controls v8, NIST CSF 2.0 and accountable owner.
- New formats: json, csv, html, checklist; `--target all`, `--priority-min`, `--domain`, `--org`.
- Maturity self-assessment (`--template`, `--assess`): weighted score, maturity level, NIST CSF and ISO views, 30/90/180-day roadmap.
- `--fail-under` exit code for CI/CD gates; `--list-targets`, `--stats`, `--version`.
- Catalogue moved to `controls_catalog.py`; examples, pytest suite and GitHub Actions added.
