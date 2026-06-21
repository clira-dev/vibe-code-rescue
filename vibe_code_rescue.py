#!/usr/bin/env python3
"""Vibe Code Rescue — diagnose, fix, and report on AI-generated web apps.

Scans a small Flask-style project for common vibe-coding failures (broken data
access, missing auth, insecure settings, logic bugs), applies deterministic
patches, and emits a before/after security report. Optional executive summary
via Claude (``ANTHROPIC_API_KEY``); offline tests use ``StubClient``.

Usage
-----
    export ANTHROPIC_API_KEY="sk-ant-..."   # optional
    python vibe_code_rescue.py sample_input/broken_app --out output/sample_report.json

Dependencies: anthropic SDK (optional at runtime) + Python standard library.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import sys
import textwrap
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ANTHROPIC_API_KEY_ENV = "ANTHROPIC_API_KEY"
DEFAULT_MODEL = "claude-opus-4-8"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

STUB_NARRATIVE = (
    "Four issues were found in the vibe-coded app: SQL injection and a wrong "
    "table name in the data layer, a missing auth guard on the admin route, "
    "insecure debug/CORS/session settings, and an inverted password check. "
    "All were patched with parameterized queries, route protection, hardened "
    "config defaults, and corrected login logic."
)

# --------------------------------------------------------------------------- #
# LLM clients
# --------------------------------------------------------------------------- #


class LLMClient(ABC):
    @abstractmethod
    def complete(self, prompt: str) -> str:
        ...


class AnthropicClient(LLMClient):
    def __init__(self, *, model: str = DEFAULT_MODEL) -> None:
        from anthropic import Anthropic

        self._client = Anthropic()
        self._model = model

    def complete(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        block = response.content[0]
        return getattr(block, "text", str(block))


class StubClient(LLMClient):
    """Deterministic offline narrative for tests and demos."""

    def __init__(self, *, narrative: str = STUB_NARRATIVE) -> None:
        self.narrative = narrative
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self.narrative


def default_client() -> LLMClient:
    if os.environ.get(ANTHROPIC_API_KEY_ENV):
        return AnthropicClient()
    return StubClient()


# --------------------------------------------------------------------------- #
# Findings model
# --------------------------------------------------------------------------- #


@dataclass
class Issue:
    id: str
    severity: str
    category: str
    file: str
    line: int
    title: str
    description: str
    fix: str


@dataclass
class DiagnosisReport:
    project: str
    scanned_at: str
    issues: list[Issue] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "scanned_at": self.scanned_at,
            "summary": self.summary,
            "issues": [asdict(i) for i in self.issues],
        }


@dataclass
class RescueReport:
    project: str
    generated_at: str
    before: DiagnosisReport
    after: DiagnosisReport
    fixes_applied: list[str]
    narrative: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "project": self.project,
            "generated_at": self.generated_at,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "fixes_applied": self.fixes_applied,
        }
        if self.narrative:
            payload["narrative"] = self.narrative
        return payload


# --------------------------------------------------------------------------- #
# Static analysis rules
# --------------------------------------------------------------------------- #

ISSUE_DEFS: list[dict[str, Any]] = [
    {
        "id": "sql_injection",
        "severity": "critical",
        "category": "data-access",
        "file": "db.py",
        "pattern": re.compile(r'f["\'].*SELECT.*\{'),
        "title": "SQL built with f-string concatenation",
        "description": "User input is interpolated into SQL, enabling injection.",
        "fix": "Use parameterized queries with ? placeholders.",
    },
    {
        "id": "wrong_table_name",
        "severity": "high",
        "category": "data-access",
        "file": "db.py",
        "pattern": re.compile(r"FROM\s+user\b", re.IGNORECASE),
        "title": "Query references non-existent table `user`",
        "description": "The schema uses `users` but the lookup queries `user`.",
        "fix": "Query the `users` table consistently.",
    },
    {
        "id": "missing_admin_auth",
        "severity": "critical",
        "category": "auth",
        "file": "app.py",
        "check": "missing_admin_auth",
        "title": "Admin route lacks authentication guard",
        "description": "/admin/users is exposed without any auth check.",
        "fix": "Require a bearer token and admin role before listing users.",
    },
    {
        "id": "insecure_debug",
        "severity": "high",
        "category": "config",
        "file": "config.py",
        "pattern": re.compile(r"^\s*DEBUG\s*=\s*True", re.MULTILINE),
        "title": "DEBUG enabled in configuration",
        "description": "Debug mode leaks stack traces and enables the Werkzeug debugger.",
        "fix": "Set DEBUG=False for production defaults.",
    },
    {
        "id": "hardcoded_secret",
        "severity": "high",
        "category": "config",
        "file": "config.py",
        "pattern": re.compile(
            r'SECRET_KEY\s*=\s*["\']DEMO-PLACEHOLDER-insecure-secret["\']'
        ),
        "title": "Hard-coded SECRET_KEY placeholder",
        "description": "Session signing key is committed in source instead of env.",
        "fix": "Load SECRET_KEY from environment with a safe dev fallback.",
    },
    {
        "id": "wildcard_cors",
        "severity": "medium",
        "category": "config",
        "file": "config.py",
        "pattern": re.compile(r"ALLOW_ALL_ORIGINS\s*=\s*True"),
        "title": "Wildcard CORS enabled",
        "description": "Any origin may call browser-authenticated endpoints.",
        "fix": "Restrict CORS to an explicit allow-list.",
    },
    {
        "id": "inverted_password_check",
        "severity": "critical",
        "category": "logic",
        "file": "app.py",
        "pattern": re.compile(r"return\s+plain\s*!=\s*stored_hash"),
        "title": "Inverted password verification logic",
        "description": "Login accepts passwords that do not match the stored hash.",
        "fix": "Return True only when plain equals the stored hash.",
    },
]


def _line_number(text: str, match: re.Match[str]) -> int:
    return text.count("\n", 0, match.start()) + 1


def _summarize(issues: list[Issue]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for issue in issues:
        counts[issue.severity] = counts.get(issue.severity, 0) + 1
    counts["total"] = len(issues)
    return counts


def _read_project_file(project: Path, name: str) -> str:
    path = project / name
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _has_missing_admin_auth(content: str) -> re.Match[str] | None:
    match = re.search(
        r'@app\.route\(["\']/admin/users["\']\)\s*\ndef\s+admin_users\s*\([^)]*\):\s*\n'
        r'(?:\s+"""[^"]*"""\s*\n)?'
        r'(\s+)(?!\s*if\s+not\s+require_admin)',
        content,
        re.MULTILINE,
    )
    return match


def _match_issue(content: str, rule: dict[str, Any]) -> re.Match[str] | None:
    checker = rule.get("check")
    if checker == "missing_admin_auth":
        return _has_missing_admin_auth(content)
    pattern = rule.get("pattern")
    if pattern is None:
        return None
    return pattern.search(content)


def diagnose(project: Path, *, scanned_at: str | None = None) -> DiagnosisReport:
    """Scan a vibe-coded app directory and return structured issues."""
    project = project.resolve()
    timestamp = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    issues: list[Issue] = []

    for rule in ISSUE_DEFS:
        rel_file = rule["file"]
        content = _read_project_file(project, rel_file)
        if not content:
            continue
        match = _match_issue(content, rule)
        if match:
            issues.append(
                Issue(
                    id=rule["id"],
                    severity=rule["severity"],
                    category=rule["category"],
                    file=rel_file,
                    line=_line_number(content, match),
                    title=rule["title"],
                    description=rule["description"],
                    fix=rule["fix"],
                )
            )

    issues.sort(key=lambda i: (SEVERITY_ORDER.index(i.severity), i.file, i.line))
    return DiagnosisReport(
        project=str(project),
        scanned_at=timestamp,
        issues=issues,
        summary=_summarize(issues),
    )


# --------------------------------------------------------------------------- #
# Deterministic fixes
# --------------------------------------------------------------------------- #

FIXED_CONFIG = textwrap.dedent(
    '''\
    """Hardened settings — secrets from env, safe production defaults."""

    import os

    DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"
    SECRET_KEY = os.environ.get("SECRET_KEY", "DEMO-PLACEHOLDER-dev-only")
    ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
        if origin.strip()
    ]
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
    SESSION_COOKIE_SECURE = True
    '''
)

FIXED_DB = textwrap.dedent(
    '''\
    """Data layer with parameterized queries."""

    import sqlite3


    def get_user_by_email(conn: sqlite3.Connection, email: str) -> dict | None:
        query = "SELECT id, email, password_hash FROM users WHERE email = ?"
        row = conn.execute(query, (email,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "email": row[1], "password_hash": row[2]}


    def list_all_users(conn: sqlite3.Connection) -> list[dict]:
        rows = conn.execute("SELECT id, email FROM users ORDER BY id").fetchall()
        return [{"id": r[0], "email": r[1]} for r in rows]
    '''
)

FIXED_APP = textwrap.dedent(
    '''\
    """Rescued Flask-style app with auth guard and correct login logic."""

    from flask import Flask, jsonify, request

    from config import DEBUG, SECRET_KEY
    from db import get_user_by_email, list_all_users

    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["DEBUG"] = DEBUG

    ADMIN_TOKEN = "DEMO-PLACEHOLDER-admin-token"


    def verify_password(plain: str, stored_hash: str) -> bool:
        return plain == stored_hash


    def require_admin() -> bool:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth.removeprefix("Bearer ").strip()
        return token == ADMIN_TOKEN


    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})


    @app.route("/login", methods=["POST"])
    def login():
        payload = request.get_json(force=True) or {}
        email = payload.get("email", "")
        password = payload.get("password", "")
        user = get_user_by_email(app.db, email)  # type: ignore[attr-defined]
        if not user:
            return jsonify({"error": "not found"}), 404
        if verify_password(password, user["password_hash"]):
            return jsonify({"token": "DEMO-PLACEHOLDER-session"})
        return jsonify({"error": "invalid credentials"}), 401


    @app.route("/admin/users")
    def admin_users():
        if not require_admin():
            return jsonify({"error": "unauthorized"}), 401
        users = list_all_users(app.db)  # type: ignore[attr-defined]
        return jsonify(users)


    if __name__ == "__main__":
        app.run(host="127.0.0.1", port=5000, debug=DEBUG)
    '''
)

FIX_MANIFEST = [
    ("config.py", FIXED_CONFIG),
    ("db.py", FIXED_DB),
    ("app.py", FIXED_APP),
]


def apply_fixes(source: Path, dest: Path) -> list[str]:
    """Copy project tree and write patched source files to dest."""
    source = source.resolve()
    dest = dest.resolve()
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(source, dest)

    applied: list[str] = []
    for rel_name, content in FIX_MANIFEST:
        target = dest / rel_name
        target.write_text(content, encoding="utf-8")
        applied.append(rel_name)
    return applied


# --------------------------------------------------------------------------- #
# Validation (offline, no server)
# --------------------------------------------------------------------------- #


def validate_fixed(project: Path) -> tuple[bool, list[str]]:
    """Return (ok, errors) for a rescued app directory."""
    project = project.resolve()
    errors: list[str] = []

    for name in ("app.py", "db.py", "config.py"):
        path = project / name
        if not path.is_file():
            errors.append(f"missing file: {name}")
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            errors.append(f"{name}: syntax error — {exc}")

    db_text = _read_project_file(project, "db.py")
    if "?" not in db_text or "f\"" in db_text or "f'" in db_text:
        errors.append("db.py: expected parameterized SQL without f-strings")
    if re.search(r"FROM\s+user\b", db_text, re.IGNORECASE):
        errors.append("db.py: still references wrong `user` table")

    app_text = _read_project_file(project, "app.py")
    if "plain != stored_hash" in app_text:
        errors.append("app.py: inverted password check still present")
    if "require_admin" not in app_text:
        errors.append("app.py: missing admin auth helper")
    if re.search(
        r'@app\.route\(["\']/admin/users["\']\)\s*\ndef\s+admin_users',
        app_text,
        re.MULTILINE,
    ):
        if "if not require_admin" not in app_text:
            errors.append("app.py: admin route missing auth guard")

    cfg_text = _read_project_file(project, "config.py")
    if re.search(r"^\s*DEBUG\s*=\s*True", cfg_text, re.MULTILINE):
        errors.append("config.py: DEBUG still hard-coded True")
    if "DEMO-PLACEHOLDER-insecure-secret" in cfg_text:
        errors.append("config.py: insecure hard-coded SECRET_KEY still present")
    if "ALLOW_ALL_ORIGINS" in cfg_text:
        errors.append("config.py: wildcard CORS flag still present")

    return (len(errors) == 0, errors)


# --------------------------------------------------------------------------- #
# Report + narrative
# --------------------------------------------------------------------------- #


def build_narrative_prompt(before: DiagnosisReport, after: DiagnosisReport) -> str:
  lines = ["Summarize this vibe-code rescue for a client (max 120 words):\n"]
  lines.append("BEFORE:")
  for issue in before.issues:
      lines.append(f"- [{issue.severity}] {issue.title} ({issue.file}:{issue.line})")
  lines.append("\nAFTER:")
  lines.append(f"- remaining issues: {after.summary.get('total', 0)}")
  lines.append(f"- fixes applied: {len(before.issues) - after.summary.get('total', 0)}")
  return "\n".join(lines)


def enrich_with_narrative(report: RescueReport, client: LLMClient) -> RescueReport:
    report.narrative = client.complete(build_narrative_prompt(report.before, report.after))
    return report


def rescue(
    source: Path,
    *,
    fixed_dir: Path,
    scanned_at: str | None = None,
    narrative: bool = False,
    client: LLMClient | None = None,
) -> RescueReport:
    """Diagnose, patch, re-scan, and optionally narrate."""
    timestamp = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    before = diagnose(source, scanned_at=timestamp)
    fixes = apply_fixes(source, fixed_dir)
    after = diagnose(fixed_dir, scanned_at=timestamp)
    report = RescueReport(
        project=str(source.resolve()),
        generated_at=timestamp,
        before=before,
        after=after,
        fixes_applied=fixes,
    )
    if narrative:
        llm = client or default_client()
        enrich_with_narrative(report, llm)
    return report


def write_report(report: RescueReport | DiagnosisReport, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Diagnose and rescue a vibe-coded Flask-style web app.",
    )
    parser.add_argument(
        "project",
        type=Path,
        help="Path to the broken app directory (e.g. sample_input/broken_app)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("output/sample_report.json"),
        help="Write JSON rescue report here",
    )
    parser.add_argument(
        "--fixed-dir",
        type=Path,
        default=Path("output/fixed_app"),
        help="Directory for patched source files",
    )
    parser.add_argument(
        "--narrative",
        action="store_true",
        help="Add Claude/Stub executive summary",
    )
    parser.add_argument(
        "--diagnose-only",
        action="store_true",
        help="Only run diagnosis (no fixes)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    project = args.project.resolve()

    if not project.is_dir():
        print(f"error: project directory not found: {project}", file=sys.stderr)
        return 2

    if args.diagnose_only:
        report = diagnose(project)
        write_report(report, args.out)
        print(f"Wrote diagnosis ({report.summary['total']} issues) → {args.out}")
        return 1 if report.summary.get("critical", 0) else 0

    rescue_report = rescue(
        project,
        fixed_dir=args.fixed_dir.resolve(),
        narrative=args.narrative,
    )
    ok, errors = validate_fixed(args.fixed_dir)
    if not ok:
        print("fixed app validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    write_report(rescue_report, args.out)
    remaining = rescue_report.after.summary.get("total", 0)
    print(
        f"Rescued {project.name}: "
        f"{rescue_report.before.summary['total']} issues → {remaining} remaining "
        f"→ {args.out}"
    )
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
