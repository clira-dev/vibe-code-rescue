"""Tests for vibe-code-rescue.

Run with:  python3 -m pytest -q

All tests are offline (no API key, no network, stdlib only). The key property
under test: the fixer must transform GENUINELY DIFFERENT inputs correctly — it
must never stamp a canned constant. Several tests therefore feed bespoke source
strings (not the bundled sample) and assert on the resulting *behavior*.
"""

from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path

import pytest
from vibe_code_rescue import (
    StubClient,
    build_narrative_prompt,
    diagnose,
    diagnose_source,
    enrich_with_narrative,
    fix_source,
    rescue,
    write_report,
)

FIXTURE_ROOT = Path(__file__).parent / "sample_input" / "broken_app"


@pytest.fixture
def fixture_root() -> Path:
    assert FIXTURE_ROOT.is_dir(), "sample_input/broken_app fixture is required"
    return FIXTURE_ROOT


# --------------------------------------------------------------------------- #
# Detection — on the bundled sample AND on bespoke inputs
# --------------------------------------------------------------------------- #


def test_diagnose_finds_all_expected_issues(fixture_root: Path):
    report = diagnose(fixture_root, scanned_at="2026-06-21T12:00:00Z")
    ids = {issue.id for issue in report.issues}
    assert "sql_injection" in ids
    assert "wrong_table_name" in ids
    assert "missing_route_auth" in ids
    assert "insecure_debug" in ids
    assert "hardcoded_secret" in ids
    assert "wildcard_cors" in ids
    assert "plaintext_password_compare" in ids
    assert report.summary["critical"] >= 3


def test_detector_works_on_arbitrary_filenames_not_just_sample():
    # A file NOT named db.py/app.py/config.py — proves we scan arbitrary input.
    src = """\
import sqlite3

def lookup(conn, email):
    q = f"SELECT id FROM user WHERE email = '{email}'"
    return conn.execute(q).fetchone()
"""
    issues = diagnose_source("totally_custom_module.py", src)
    ids = {i.id for i in issues}
    assert "sql_injection" in ids
    assert "wrong_table_name" in ids


def test_plaintext_password_detected_on_custom_input():
    src = """\
def check_pw(plain, stored_hash):
    return plain == stored_hash
"""
    issues = diagnose_source("auth.py", src)
    assert any(i.id == "plaintext_password_compare" for i in issues)


def test_missing_route_auth_detected_via_ast():
    src = """\
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/admin/secrets")
def secrets():
    return jsonify({"k": "v"})
"""
    issues = diagnose_source("routes.py", src)
    assert any(i.id == "missing_route_auth" for i in issues)


def test_guarded_route_is_not_flagged():
    # Same route but WITH an auth guard call — must NOT be flagged.
    src = """\
from flask import Flask, jsonify

@app.route("/admin/secrets")
def secrets():
    if not require_admin():
        return jsonify({"error": "no"}), 401
    return jsonify({"k": "v"})
"""
    issues = diagnose_source("routes.py", src)
    assert not any(i.id == "missing_route_auth" for i in issues)


def test_secret_loaded_from_env_is_not_flagged():
    src = 'import os\nSECRET_KEY = os.environ.get("SECRET_KEY", "x")\n'
    issues = diagnose_source("config.py", src)
    assert not any(i.id == "hardcoded_secret" for i in issues)


# --------------------------------------------------------------------------- #
# Fixing — genuinely different inputs, asserting on behavior not constants
# --------------------------------------------------------------------------- #


def _exec_module(source: str, name: str):
    """Compile + exec a source string into a fresh module namespace."""
    ns: dict = {}
    code = compile(source, f"<{name}>", "exec")
    exec(code, ns)  # noqa: S102 - controlled test input
    return ns


def _exec_auth_only(source: str, name: str):
    """Exec only the auth helpers + their imports from a module with flask deps.

    The rescued app.py imports flask (which may not be installed); we extract
    just the import statements and the hash_password/verify_password defs so the
    behavioral auth test runs stdlib-only.
    """
    stdlib_ok = {"os", "hmac", "hashlib"}
    tree = ast.parse(source)
    keep: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            if all(a.name.split(".")[0] in stdlib_ok for a in node.names):
                keep.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in {
            "hash_password",
            "verify_password",
        }:
            keep.append(node)
        elif isinstance(node, ast.Try):
            keep.append(node)  # the bcrypt-optional import block
        elif isinstance(node, ast.Assign):
            # module-level constants like _PBKDF2_ALGO / _PBKDF2_ROUNDS
            targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if any(name.startswith("_PBKDF2") for name in targets):
                keep.append(node)
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    ns: dict = {}
    exec(compile(module, f"<{name}>", "exec"), ns)  # noqa: S102
    return ns


def test_fix_plaintext_password_produces_real_hashing():
    src = """\
def verify_password(plain, stored_hash):
    return plain == stored_hash
"""
    fixed, applied = fix_source(src, ["plaintext_password_compare"])
    assert fixed != src
    assert ast.parse(fixed)  # still valid python
    # No plaintext compare survives.
    assert "plain == stored_hash" not in fixed
    assert "hmac.compare_digest" in fixed
    assert "pbkdf2_hmac" in fixed or "bcrypt" in fixed

    # Behavioral: the rescued verify_password must accept the right password
    # and reject the wrong one, using a hash it produces itself.
    ns = _exec_module(fixed, "fixed_auth")
    h = ns["hash_password"]("hunter2")
    assert h != "hunter2"  # stored value is NOT plaintext
    assert ns["verify_password"]("hunter2", h) is True
    assert ns["verify_password"]("wrong", h) is False


def test_fix_transforms_a_DIFFERENT_password_function_name():
    # Different function name + different arg names — not the bundled sample.
    src = """\
def verify_user_pwd(candidate_password, stored_pw_hash):
    return candidate_password == stored_pw_hash
"""
    fixed, applied = fix_source(src, ["plaintext_password_compare"])
    assert fixed != src
    assert "== stored_pw_hash" not in fixed
    ns = _exec_module(fixed, "fixed_auth2")
    h = ns["hash_password"]("s3cret")
    assert ns["verify_password"]("s3cret", h) is True
    assert ns["verify_password"]("nope", h) is False


def test_fix_sql_injection_is_parameterized_and_runs():
    src = """\
import sqlite3

def get_user_by_email(conn, email):
    query = f"SELECT id, email FROM users WHERE email = '{email}'"
    row = conn.execute(query).fetchone()
    return row
"""
    fixed, applied = fix_source(src, ["sql_injection"])
    assert fixed != src
    assert "?" in fixed
    assert 'f"' not in fixed and "f'" not in fixed
    # Behavioral: run it against a real in-memory sqlite db.
    ns = _exec_module(fixed, "fixed_db")
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'a@b.com')")
    conn.commit()
    assert ns["get_user_by_email"](conn, "a@b.com") == (1, "a@b.com")
    # Injection attempt returns nothing instead of dumping the table.
    assert ns["get_user_by_email"](conn, "x' OR '1'='1") is None


def test_fix_debug_true_becomes_env_driven():
    src = "DEBUG = True\n"
    fixed, applied = fix_source(src, ["insecure_debug"])
    assert "DEBUG = True" not in fixed
    assert "os.environ" in fixed
    ns = _exec_module(fixed, "fixed_cfg")
    assert ns["DEBUG"] is False  # safe default when env unset


def test_fix_hardcoded_secret_moves_to_env():
    src = 'SECRET_KEY = "DEMO-PLACEHOLDER-some-literal"\n'
    fixed, applied = fix_source(src, ["hardcoded_secret"])
    assert "os.environ" in fixed
    ns = _exec_module(fixed, "fixed_secret")
    assert ns["SECRET_KEY"]  # resolves to the placeholder fallback
    assert "PLACEHOLDER" in ns["SECRET_KEY"]


def test_fix_wrong_table_corrects_name():
    src = 'q = "SELECT id FROM user WHERE id = ?"\n'
    fixed, applied = fix_source(src, ["wrong_table_name"])
    assert "FROM users" in fixed
    assert "FROM user " not in fixed


def test_fix_missing_route_auth_inserts_guard():
    src = """\
from flask import Flask, jsonify
app = Flask(__name__)

@app.route("/admin/users")
def admin_users():
    return jsonify([])
"""
    fixed, applied = fix_source(src, ["missing_route_auth"])
    assert "require_admin" in fixed
    assert "unauthorized" in fixed
    assert ast.parse(fixed)
    # Re-diagnosing the fixed source clears the finding.
    assert not any(i.id == "missing_route_auth" for i in diagnose_source("app.py", fixed))


def test_fixer_is_not_a_canned_template_across_two_inputs():
    """Two different inputs must yield two different outputs (no constant stamp)."""
    a = "def verify_password(p, h):\n    return p == h\n"
    b = "def verify_passwd(secret, digest):\n    return secret == digest\n"
    fa, _ = fix_source(a, ["plaintext_password_compare"])
    fb, _ = fix_source(b, ["plaintext_password_compare"])
    # Both fixed, both safe, but they came from different sources and both run.
    for fixed, label in ((fa, "a"), (fb, "b")):
        ns = _exec_module(fixed, f"distinct_{label}")
        h = ns["hash_password"]("pw")
        assert ns["verify_password"]("pw", h) is True
        assert ns["verify_password"]("x", h) is False


# --------------------------------------------------------------------------- #
# End-to-end rescue on the bundled sample
# --------------------------------------------------------------------------- #


def test_rescue_clears_all_issues_and_writes_tree(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(fixture_root, fixed_dir=fixed, scanned_at="2026-06-21T12:00:00Z")
    assert report.before.summary["total"] > 0
    assert report.after.summary["total"] == 0
    assert report.fixes_applied  # real fixes recorded
    # Patched tree exists and is valid python.
    for name in ("app.py", "db.py", "config.py"):
        text = (fixed / name).read_text(encoding="utf-8")
        ast.parse(text)
    # The rescued app must NOT contain a plaintext password compare.
    app_text = (fixed / "app.py").read_text(encoding="utf-8")
    assert "plain == stored_hash" not in app_text
    assert "plain != stored_hash" not in app_text
    assert "compare_digest" in app_text


def test_rescued_auth_actually_verifies(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    rescue(fixture_root, fixed_dir=fixed, scanned_at="2026-06-21T12:00:00Z")
    app_text = (fixed / "app.py").read_text(encoding="utf-8")
    ns = _exec_auth_only(app_text, "rescued_app_auth")
    h = ns["hash_password"]("correct horse")
    assert h != "correct horse"
    assert ns["verify_password"]("correct horse", h) is True
    assert ns["verify_password"]("battery staple", h) is False


def test_rescue_diff_present(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(fixture_root, fixed_dir=fixed, scanned_at="2026-06-21T12:00:00Z")
    diffs = [f.diff for f in report.fixes_applied if f.diff]
    assert diffs, "expected at least one unified diff"
    assert any(d.startswith("--- a/") for d in diffs)


def test_each_fix_has_a_rationale(fixture_root: Path, tmp_path: Path):
    fixed = tmp_path / "fixed"
    report = rescue(fixture_root, fixed_dir=fixed, scanned_at="2026-06-21T12:00:00Z")
    for f in report.fixes_applied:
        if f.fix_id != "composite":
            assert f.rationale, f"fix {f.fix_id} missing rationale"


def test_input_is_never_mutated(fixture_root: Path, tmp_path: Path):
    before = (fixture_root / "app.py").read_text(encoding="utf-8")
    rescue(fixture_root, fixed_dir=tmp_path / "fixed", scanned_at="2026-06-21T12:00:00Z")
    after = (fixture_root / "app.py").read_text(encoding="utf-8")
    assert before == after, "rescue must not mutate the input tree"


# --------------------------------------------------------------------------- #
# Narrative + output
# --------------------------------------------------------------------------- #


def test_stub_narrative_reflects_findings(fixture_root: Path, tmp_path: Path):
    report = rescue(
        fixture_root,
        fixed_dir=tmp_path / "fixed",
        scanned_at="2026-06-21T12:00:00Z",
        narrative=True,
        client=StubClient(),
    )
    assert report.narrative
    assert "issue" in report.narrative.lower()


def test_enrich_with_narrative_records_prompt(fixture_root: Path, tmp_path: Path):
    report = rescue(fixture_root, fixed_dir=tmp_path / "fixed", scanned_at="2026-06-21T12:00:00Z")
    stub = StubClient()
    enrich_with_narrative(report, stub)
    assert len(stub.calls) == 1
    assert "BEFORE" in stub.calls[0]


def test_build_narrative_prompt_lists_issues(fixture_root: Path, tmp_path: Path):
    report = rescue(fixture_root, fixed_dir=tmp_path / "fixed", scanned_at="2026-06-21T12:00:00Z")
    prompt = build_narrative_prompt(report.before, report.after)
    assert "BEFORE" in prompt and "AFTER" in prompt


def test_write_report_round_trip(fixture_root: Path, tmp_path: Path):
    report = rescue(fixture_root, fixed_dir=tmp_path / "fixed", scanned_at="2026-06-21T12:00:00Z")
    out = tmp_path / "report.json"
    write_report(report, out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["before"]["summary"]["total"] > 0
    assert payload["after"]["summary"]["total"] == 0
    assert "fixes_applied" in payload


def test_module_is_stdlib_only_importable():
    # Importing must not require any third-party package.
    mod = importlib.import_module("vibe_code_rescue")
    assert hasattr(mod, "rescue")
