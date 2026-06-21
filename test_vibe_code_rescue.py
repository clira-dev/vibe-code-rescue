"""Tests for vibe-code-rescue.

Run with:  pytest -q

All tests use local fixtures and StubClient — no API key or network required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibe_code_rescue import (
    STUB_NARRATIVE,
    StubClient,
    apply_fixes,
    diagnose,
    enrich_with_narrative,
    rescue,
    validate_fixed,
    write_report,
)

FIXTURE_ROOT = Path("sample_input/broken_app")


@pytest.fixture
def fixture_root() -> Path:
    assert FIXTURE_ROOT.is_dir(), "sample_input/broken_app fixture is required"
    return FIXTURE_ROOT


@pytest.fixture
def fixed_root(fixture_root: Path, tmp_path: Path) -> Path:
    dest = tmp_path / "fixed_app"
    apply_fixes(fixture_root, dest)
    return dest


# --------------------------------------------------------------------------- #
# Diagnosis
# --------------------------------------------------------------------------- #


def test_diagnose_finds_all_expected_issues(fixture_root: Path):
    report = diagnose(fixture_root, scanned_at="2025-06-21T12:00:00Z")
    ids = {issue.id for issue in report.issues}

    assert "sql_injection" in ids
    assert "wrong_table_name" in ids
    assert "missing_admin_auth" in ids
    assert "insecure_debug" in ids
    assert "hardcoded_secret" in ids
    assert "wildcard_cors" in ids
    assert "inverted_password_check" in ids
    assert report.summary["total"] == 7
    assert report.summary["critical"] >= 3


def test_diagnose_issues_have_line_numbers(fixture_root: Path):
    report = diagnose(fixture_root, scanned_at="2025-06-21T12:00:00Z")
    for issue in report.issues:
        assert issue.line >= 1
        assert issue.file in {"app.py", "db.py", "config.py"}
        assert issue.title
        assert issue.fix


def test_diagnose_sorted_by_severity(fixture_root: Path):
    report = diagnose(fixture_root, scanned_at="2025-06-21T12:00:00Z")
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(i.severity) for i in report.issues]
    assert ranks == sorted(ranks)


# --------------------------------------------------------------------------- #
# Fixes + validation
# --------------------------------------------------------------------------- #


def test_apply_fixes_writes_patched_files(fixture_root: Path, tmp_path: Path):
    dest = tmp_path / "fixed"
    applied = apply_fixes(fixture_root, dest)

    assert set(applied) == {"app.py", "db.py", "config.py"}
    assert (dest / "app.py").is_file()
    assert (dest / "db.py").is_file()
    assert (dest / "config.py").is_file()


def test_fixed_version_passes_validation(fixed_root: Path):
    ok, errors = validate_fixed(fixed_root)
    assert ok, errors


def test_fixed_version_has_no_remaining_issues(fixed_root: Path):
    report = diagnose(fixed_root, scanned_at="2025-06-21T12:00:00Z")
    assert report.summary["total"] == 0


def test_rescue_report_before_after(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(
        fixture_root,
        fixed_dir=fixed,
        scanned_at="2025-06-21T12:00:00Z",
    )

    assert report.before.summary["total"] == 7
    assert report.after.summary["total"] == 0
    assert len(report.fixes_applied) == 3
    ok, errors = validate_fixed(fixed)
    assert ok, errors


# --------------------------------------------------------------------------- #
# Narrative + output
# --------------------------------------------------------------------------- #


def test_stub_client_narrative(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(
        fixture_root,
        fixed_dir=fixed,
        scanned_at="2025-06-21T12:00:00Z",
        narrative=True,
        client=StubClient(),
    )
    assert report.narrative == STUB_NARRATIVE


def test_enrich_with_narrative_records_prompt(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(fixture_root, fixed_dir=fixed, scanned_at="2025-06-21T12:00:00Z")
    stub = StubClient()
    enrich_with_narrative(report, stub)
    assert len(stub.calls) == 1
    assert "sql_injection" in stub.calls[0] or "SQL" in stub.calls[0]


def test_write_report_round_trip(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(fixture_root, fixed_dir=fixed, scanned_at="2025-06-21T12:00:00Z")
    out = tmp_path / "report.json"
    write_report(report, out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["before"]["summary"]["total"] == 7
    assert payload["after"]["summary"]["total"] == 0
    assert "fixes_applied" in payload


# --------------------------------------------------------------------------- #
# Committed sample output parity
# --------------------------------------------------------------------------- #


def test_committed_sample_report_matches_fixture(fixture_root: Path, tmp_path: Path):
    sample = Path("output/sample_report.json")
    if not sample.is_file():
        pytest.skip("committed sample_report.json not present yet")

    payload = json.loads(sample.read_text(encoding="utf-8"))
    live = rescue(
        fixture_root,
        fixed_dir=tmp_path / "fixed",
        scanned_at=payload["generated_at"],
    )
    assert live.before.summary == payload["before"]["summary"]
    assert live.after.summary == payload["after"]["summary"]
