import csv
import io
import json

import pytest

import best_practices_generator as g
from controls_catalog import BEST_PRACTICES, DOMAIN_METADATA, ISO27001_TITLES


def test_catalogue_integrity():
    ids = [c["id"] for t in BEST_PRACTICES.values() for d in t.values() for c in d]
    assert len(ids) == len(set(ids)) == 145
    for target in BEST_PRACTICES.values():
        for domain, controls in target.items():
            assert domain in DOMAIN_METADATA
            assert all(c["priority"].split()[0] in {"P1", "P2", "P3"} for c in controls)
    for meta in DOMAIN_METADATA.values():
        assert set(meta["iso27001"]) <= set(ISO27001_TITLES)


def test_priority_and_domain_filters():
    p1 = g.select_controls(["windows"], priority_min="P1")
    assert p1 and all(r["priority_code"] == "P1" for r in p1)
    p2 = g.select_controls(["windows"], priority_min="P2")
    assert {r["priority_code"] for r in p2} == {"P1", "P2"}
    tls = g.select_controls(["webserver"], domains=["tls"])
    assert {r["domain"] for r in tls} == {"Network & TLS"}


@pytest.mark.parametrize("fmt", sorted(g.BASELINE_RENDERERS))
def test_every_format_renders(fmt, capsys):
    assert g.main(["--target", "cloud", "--format", fmt, "--org", "ACME"]) == 0
    out = capsys.readouterr().out
    assert "CLD-IAM-01" in out


def test_json_and_csv_contain_mappings():
    rows = g.select_controls(["active_directory"])
    data = json.loads(g.render_json(rows, ["active_directory"]))
    assert data["count"] == 25 and "iso27001" in data["controls"][0]
    reader = list(csv.DictReader(io.StringIO(g.render_csv(rows, ["active_directory"]))))
    assert reader[0]["nist_csf"] and reader[0]["owner"]


def test_html_escapes_organization():
    page = g.render_html(g.select_controls(["linux"]), ["linux"], org="<script>x</script>")
    assert "<script>x" not in page and "&lt;script&gt;" in page


def _answers(target, default="implemented", **overrides):
    rows = g.select_controls([target])
    answers = {r["id"]: default for r in rows}
    answers.update(overrides)
    return {"organization": "Test", "targets": [target], "answers": answers}


def test_full_implementation_scores_100():
    result = g.assess(_answers("linux"))
    assert result["overall_score"] == 100.0
    assert result["maturity"].startswith("5")
    assert all(not items for items in result["roadmap"].values())


def test_priority_weighting_and_roadmap():
    # Missing one P1 control costs more than missing one P3 control.
    p1_gap = g.assess(_answers("windows", **{"WIN-ACC-01": "not_implemented"}))
    p3_gap = g.assess(_answers("windows", **{"WIN-ACC-05": "not_implemented"}))
    assert p1_gap["overall_score"] < p3_gap["overall_score"]
    assert p1_gap["critical_gaps"] == 1
    assert p1_gap["roadmap"]["0-30 days"][0]["id"] == "WIN-ACC-01"
    assert p3_gap["roadmap"]["91-180 days"][0]["id"] == "WIN-ACC-05"


def test_partial_and_not_applicable():
    partial = g.assess(_answers("cloud", **{"CLD-IAM-01": "partial"}))
    missing = g.assess(_answers("cloud", **{"CLD-IAM-01": "not_implemented"}))
    na = g.assess(_answers("cloud", **{"CLD-IAM-01": "not_applicable"}))
    assert missing["overall_score"] < partial["overall_score"] < 100 == na["overall_score"]


def test_unanswered_counted_and_invalid_rejected():
    doc = _answers("linux")
    doc["answers"].pop("LNX-ACC-01")
    assert g.assess(doc)["unanswered"] == 1
    doc["answers"]["LNX-ACC-02"] = "done"
    with pytest.raises(ValueError):
        g.assess(doc)


def test_template_then_assess_and_ci_gate(tmp_path, capsys):
    template = tmp_path / "answers.json"
    assert g.main(["--target", "active_directory", "--template", "--output", str(template)]) == 0
    assert g.main(["--assess", str(template), "--format", "markdown", "--fail-under", "50"]) == 2
    out = capsys.readouterr().out
    assert "Remediation roadmap" in out and "NIST CSF 2.0" in out


def test_cli_requires_a_mode():
    with pytest.raises(SystemExit):
        g.parse_arguments([])
