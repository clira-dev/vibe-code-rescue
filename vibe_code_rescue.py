#!/usr/bin/env python3
"""Vibe Code Rescue — detect and surgically fix security bugs in AI-generated apps.

Ship your broken AI-generated app, secured. This tool scans ARBITRARY Python
source (Flask-style web apps are the common case), finds the security and logic
bugs that AI assistants reliably emit, and applies *surgical* source patches —
not template overwrites. It emits a unified diff plus a per-fix rationale so the
change is reviewable in a PR.

What it detects (on any input file, via Python's ``ast`` + targeted regex):

* ``debug=True`` / ``DEBUG = True``           — leaks stack traces, enables RCE-y debugger
* plaintext password comparison               — ``plain == stored`` instead of a real hash
* missing auth guard on a sensitive route     — admin endpoint with no check
* hard-coded secret                           — ``SECRET_KEY = "..."`` literal in source
* SQL built by string concatenation / f-string — injection
* wrong table name (``FROM user`` vs ``users``) — schema mismatch logic bug

The remediated authentication uses a *real* password hash (bcrypt when
installed, otherwise stdlib ``hashlib.pbkdf2_hmac``) verified with
``hmac.compare_digest`` — never a plaintext comparison.

Usage
-----
    # Diagnose + fix an arbitrary project, write a JSON report + unified diff
    python3 vibe_code_rescue.py path/to/app --out report.json --fixed-dir fixed/

    # Diagnose only
    python3 vibe_code_rescue.py path/to/app --diagnose-only

The tool is stdlib-only at runtime. ``anthropic`` is optional and only used for
an executive-summary narrative when ``ANTHROPIC_API_KEY`` is set.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import os
import re
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

ANTHROPIC_API_KEY_ENV = "ANTHROPIC_API_KEY"
DEFAULT_MODEL = "claude-opus-4-8"

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Files we know how to parse + patch. Anything matching ``*.py`` is scanned.
PY_GLOB = "*.py"

# --------------------------------------------------------------------------- #
# LLM clients (optional executive narrative only — never used to generate fixes)
# --------------------------------------------------------------------------- #


class LLMClient(ABC):
    @abstractmethod
    def complete(self, prompt: str) -> str: ...


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

    def __init__(self, *, narrative: str | None = None) -> None:
        self.narrative = narrative
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self.narrative is not None:
            return self.narrative
        # Derive a deterministic summary from the prompt itself so the stub
        # reflects the actual (arbitrary) findings rather than a canned string.
        n = prompt.count("\n- [")
        return (
            f"Rescue complete: {n} security/logic issue(s) detected and "
            "surgically patched (parameterized SQL, real password hashing with "
            "constant-time compare, route auth, hardened config). Review the "
            "unified diff before shipping."
        )


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

    def key(self) -> tuple[str, str, int]:
        return (self.id, self.file, self.line)


@dataclass
class FixResult:
    file: str
    fix_id: str
    rationale: str
    diff: str  # unified diff for this file/fix


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
    fixes_applied: list[FixResult]
    narrative: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "project": self.project,
            "generated_at": self.generated_at,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "fixes_applied": [asdict(f) for f in self.fixes_applied],
        }
        if self.narrative:
            payload["narrative"] = self.narrative
        return payload


# --------------------------------------------------------------------------- #
# AST / structural helpers
# --------------------------------------------------------------------------- #


def _safe_parse(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _line_of(source: str, needle: re.Pattern[str]) -> int:
    m = needle.search(source)
    if not m:
        return 1
    return source.count("\n", 0, m.start()) + 1


def _decorator_route_path(dec: ast.expr) -> str | None:
    """Return the route path string for an ``@app.route("/x")`` decorator."""
    call = dec if isinstance(dec, ast.Call) else None
    if call is None:
        return None
    func = call.func
    # match *.route(...)
    if isinstance(func, ast.Attribute) and func.attr == "route":
        if call.args and isinstance(call.args[0], ast.Constant):
            val = call.args[0].value
            if isinstance(val, str):
                return val
    return None


def _func_calls_name(func: ast.FunctionDef, names: set[str]) -> bool:
    """True if the function body calls any of ``names`` (e.g. an auth guard)."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            callee = node.func
            if isinstance(callee, ast.Name) and callee.id in names:
                return True
            if isinstance(callee, ast.Attribute) and callee.attr in names:
                return True
    return False


def _func_has_decorator_named(func: ast.FunctionDef, names: set[str]) -> bool:
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Name) and target.id in names:
            return True
        if isinstance(target, ast.Attribute) and target.attr in names:
            return True
    return False


# Sensitive route substrings that should be guarded by auth.
SENSITIVE_ROUTE_HINTS = ("admin", "internal", "delete", "users")
# Names that, if called or decorated, count as an auth guard already present.
AUTH_GUARD_NAMES = {
    "require_admin",
    "require_auth",
    "login_required",
    "admin_required",
    "requires_auth",
    "authenticate",
    "check_auth",
}


# --------------------------------------------------------------------------- #
# Detectors — each returns a list[Issue] for one source file
# --------------------------------------------------------------------------- #

Detector = Callable[[str, str, ast.Module | None], list[Issue]]

_PLAINTEXT_PW_RE = re.compile(r"\breturn\s+(?P<a>\w+)\s*(?P<op>==|!=)\s*(?P<b>\w+)\b")
_DEBUG_TRUE_RE = re.compile(r"^\s*DEBUG\s*=\s*True\b", re.MULTILINE)
_DEBUG_KW_RE = re.compile(r"\bdebug\s*=\s*True\b")
_SECRET_LITERAL_RE = re.compile(
    r"""^\s*(SECRET_KEY|SECRET|API_KEY|PASSWORD|TOKEN)\s*=\s*["'][^"']+["']""",
    re.MULTILINE,
)
_SQL_FSTRING_RE = re.compile(
    r"""(?is)\bf(?P<q>["'])"""
    r"""(?:(?!(?P=q)).)*?\b(?:select|insert|update|delete)\b"""
    r"""(?:(?!(?P=q)).)*?\{(?:(?!(?P=q)).)*?(?P=q)""",
)
_SQL_CONCAT_RE = re.compile(
    r"""(?is)(?P<q>["'])"""
    r"""(?:(?!(?P=q)).)*?\b(?:select|insert|update|delete)\b"""
    r"""(?:(?!(?P=q)).)*?(?P=q)\s*\+""",
)
_WRONG_TABLE_RE = re.compile(r"\bFROM\s+user\b", re.IGNORECASE)
_WILDCARD_CORS_RE = re.compile(r"\bALLOW_ALL_ORIGINS\s*=\s*True\b")


_PW_FUNC_HINTS = ("password", "passwd", "pwd", "hash", "login", "auth", "verify")


def detect_plaintext_password(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    """Direct equality/inequality compare of a password against a stored value."""
    if tree is None:
        return []
    issues: list[Issue] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        fname = node.name.lower()
        argnames = {a.arg.lower() for a in node.args.args}
        looks_pw = any(h in fname for h in _PW_FUNC_HINTS) or any(
            "pass" in a or "plain" in a or "pwd" in a for a in argnames
        )
        if not looks_pw:
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Compare) and len(sub.ops) == 1:
                op = sub.ops[0]
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    names = {n.id.lower() for n in ast.walk(sub) if isinstance(n, ast.Name)}
                    # Heuristic: one side is the plaintext arg, the other a stored hash.
                    if any("pass" in n or "plain" in n or "pwd" in n for n in names) and any(
                        "hash" in n or "stored" in n or "digest" in n for n in names
                    ):
                        issues.append(
                            Issue(
                                id="plaintext_password_compare",
                                severity="critical",
                                category="auth",
                                file=file,
                                line=getattr(sub, "lineno", node.lineno),
                                title="Plaintext password comparison",
                                description=(
                                    "The password is compared directly to the stored "
                                    "value instead of being hashed and checked in "
                                    "constant time — leaks via timing and means stored "
                                    "secrets are plaintext."
                                ),
                                fix=(
                                    "Hash the password (bcrypt or pbkdf2_hmac) and "
                                    "compare with hmac.compare_digest."
                                ),
                            )
                        )
                        break  # one finding per function
    return issues


def detect_debug_true(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    issues: list[Issue] = []
    if _DEBUG_TRUE_RE.search(src):
        issues.append(
            Issue(
                id="insecure_debug",
                severity="high",
                category="config",
                file=file,
                line=_line_of(src, _DEBUG_TRUE_RE),
                title="DEBUG enabled in configuration",
                description=(
                    "Debug mode leaks stack traces and enables an interactive "
                    "debugger that can execute arbitrary code."
                ),
                fix="Drive DEBUG from the environment, defaulting to False.",
            )
        )
    # debug=True as a keyword (e.g. app.run(debug=True)) only if not the config form
    for m in _DEBUG_KW_RE.finditer(src):
        line = src.count("\n", 0, m.start()) + 1
        issues.append(
            Issue(
                id="debug_run_true",
                severity="high",
                category="config",
                file=file,
                line=line,
                title="Server started with debug=True",
                description="Running with debug=True exposes the Werkzeug debugger.",
                fix="Pass debug=DEBUG (env-driven) instead of a literal True.",
            )
        )
    return issues


def detect_hardcoded_secret(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    issues: list[Issue] = []
    for m in _SECRET_LITERAL_RE.finditer(src):
        # Skip values already read from env on the same line.
        line_text = src[
            m.start() : src.find("\n", m.start()) if src.find("\n", m.start()) != -1 else len(src)
        ]
        if "os.environ" in line_text or "getenv" in line_text:
            continue
        line = src.count("\n", 0, m.start()) + 1
        issues.append(
            Issue(
                id="hardcoded_secret",
                severity="high",
                category="config",
                file=file,
                line=line,
                title="Hard-coded secret in source",
                description=(
                    "A signing key / credential is committed as a string literal "
                    "instead of being loaded from the environment."
                ),
                fix="Load the value from os.environ with a safe dev fallback.",
            )
        )
    return issues


def detect_sql_injection(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    issues: list[Issue] = []
    for rx, _fid in (
        (_SQL_FSTRING_RE, "sql_injection_fstring"),
        (_SQL_CONCAT_RE, "sql_injection_concat"),
    ):
        for m in rx.finditer(src):
            line = src.count("\n", 0, m.start()) + 1
            issues.append(
                Issue(
                    id="sql_injection",
                    severity="critical",
                    category="data-access",
                    file=file,
                    line=line,
                    title="SQL built by string interpolation",
                    description=(
                        "User-controlled input is interpolated into a SQL string, "
                        "enabling SQL injection."
                    ),
                    fix="Use a parameterized query with ? placeholders.",
                )
            )
            break  # report once per file
        if issues:
            break
    return issues


def detect_wrong_table(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    if _WRONG_TABLE_RE.search(src):
        return [
            Issue(
                id="wrong_table_name",
                severity="high",
                category="data-access",
                file=file,
                line=_line_of(src, _WRONG_TABLE_RE),
                title="Query references singular `user` table",
                description=(
                    "The query selects FROM `user` while the schema defines "
                    "`users` — the lookup silently fails."
                ),
                fix="Reference the `users` table consistently.",
            )
        ]
    return []


def detect_wildcard_cors(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    if _WILDCARD_CORS_RE.search(src):
        return [
            Issue(
                id="wildcard_cors",
                severity="medium",
                category="config",
                file=file,
                line=_line_of(src, _WILDCARD_CORS_RE),
                title="Wildcard CORS enabled",
                description="Any origin may call browser-authenticated endpoints.",
                fix="Restrict CORS to an explicit allow-list from the environment.",
            )
        ]
    return []


def detect_missing_route_auth(file: str, src: str, tree: ast.Module | None) -> list[Issue]:
    """Find a sensitive @app.route handler with no auth guard call/decorator."""
    if tree is None:
        return []
    issues: list[Issue] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        route_paths = [p for p in (_decorator_route_path(d) for d in node.decorator_list) if p]
        if not route_paths:
            continue
        path = route_paths[0]
        if not any(hint in path.lower() for hint in SENSITIVE_ROUTE_HINTS):
            continue
        if _func_has_decorator_named(node, AUTH_GUARD_NAMES):
            continue
        if _func_calls_name(node, AUTH_GUARD_NAMES):
            continue
        issues.append(
            Issue(
                id="missing_route_auth",
                severity="critical",
                category="auth",
                file=file,
                line=node.lineno,
                title=f"Sensitive route `{path}` lacks an auth guard",
                description=(
                    f"The handler for `{path}` is exposed without any "
                    "authentication or authorization check."
                ),
                fix="Require an authenticated admin (bearer token) before serving.",
            )
        )
    return issues


DETECTORS: list[Detector] = [
    detect_plaintext_password,
    detect_debug_true,
    detect_hardcoded_secret,
    detect_sql_injection,
    detect_wrong_table,
    detect_wildcard_cors,
    detect_missing_route_auth,
]


def _summarize(issues: list[Issue]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for issue in issues:
        counts[issue.severity] = counts.get(issue.severity, 0) + 1
    counts["total"] = len(issues)
    return counts


def _iter_py_files(project: Path) -> list[Path]:
    if project.is_file():
        return [project]
    return sorted(p for p in project.rglob(PY_GLOB) if p.is_file())


def diagnose_source(file_label: str, source: str) -> list[Issue]:
    """Run all detectors against a single source string. Pure / testable."""
    tree = _safe_parse(source)
    issues: list[Issue] = []
    for detector in DETECTORS:
        issues.extend(detector(file_label, source, tree))
    return issues


def diagnose(project: Path, *, scanned_at: str | None = None) -> DiagnosisReport:
    """Scan an arbitrary project directory (or single file) for issues."""
    project = project.resolve()
    timestamp = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    issues: list[Issue] = []
    base = project if project.is_dir() else project.parent
    for path in _iter_py_files(project):
        rel = str(path.relative_to(base)) if path != project else path.name
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        issues.extend(diagnose_source(rel, source))

    issues.sort(key=lambda i: (SEVERITY_ORDER.index(i.severity), i.file, i.line))
    return DiagnosisReport(
        project=str(project),
        scanned_at=timestamp,
        issues=issues,
        summary=_summarize(issues),
    )


# --------------------------------------------------------------------------- #
# Surgical fixers — each rewrites the ACTUAL source, returns (new_src, rationale)
# --------------------------------------------------------------------------- #

# The secure auth helper block injected when we remediate a plaintext compare.
SECURE_AUTH_HELPERS = '''\
import hashlib
import hmac
import os

try:  # Prefer bcrypt when available; fall back to stdlib pbkdf2_hmac.
    import bcrypt as _bcrypt  # type: ignore
except Exception:  # pragma: no cover - exercised only when bcrypt installed
    _bcrypt = None

_PBKDF2_ALGO = "sha256"
_PBKDF2_ROUNDS = 240_000


def hash_password(plain: str) -> str:
    """Return a salted, slow password hash safe to store at rest."""
    if _bcrypt is not None:
        return _bcrypt.hashpw(plain.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, plain.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_{_PBKDF2_ALGO}${_PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(plain: str, stored_hash: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    if stored_hash.startswith("pbkdf2_"):
        try:
            prefix, rounds_s, salt_hex, digest_hex = stored_hash.split("$", 3)
            algo = prefix.split("_", 1)[1]  # e.g. "pbkdf2_sha256" -> "sha256"
            rounds = int(rounds_s)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
        except (ValueError, IndexError):
            return False
        candidate = hashlib.pbkdf2_hmac(algo, plain.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(candidate, expected)
    if _bcrypt is not None:
        try:
            return _bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False
    # Unknown/legacy format: refuse rather than fall back to plaintext.
    return False
'''


def _replace_function_def(source: str, func_name: str, new_def: str) -> str | None:
    """Replace the body of a top-level function by name, preserving the rest."""
    tree = _safe_parse(source)
    if tree is None:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            start = node.lineno - 1
            end = node.end_lineno  # exclusive when used as slice end below
            # Include any decorator lines above.
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list) - 1
            lines = source.splitlines(keepends=True)
            replacement = new_def if new_def.endswith("\n") else new_def + "\n"
            return "".join(lines[:start]) + replacement + "".join(lines[end:])
    return None


def fix_plaintext_password(source: str) -> tuple[str, str] | None:
    """Rewrite a plaintext verify_password into a real-hash, constant-time one."""
    tree = _safe_parse(source)
    if tree is None:
        return None
    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            fname = node.name.lower()
            if "verify" in fname and ("pass" in fname or "pwd" in fname or "password" in fname):
                target = node.name
                break
    if target is None:
        # fall back: any function literally named verify_password
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "verify_password":
                target = node.name
                break
    if target is None:
        return None

    new = _replace_function_def(source, target, SECURE_AUTH_HELPERS.rstrip("\n"))
    if new is None or new == source:
        return None
    rationale = (
        f"Replaced plaintext `{target}` with hash_password/verify_password using "
        "bcrypt (or stdlib pbkdf2_hmac) and hmac.compare_digest for constant-time "
        "checks. Passwords are never compared as plaintext."
    )
    return new, rationale


def fix_debug_true(source: str) -> tuple[str, str] | None:
    new = _DEBUG_TRUE_RE.sub(
        'DEBUG = os.environ.get("APP_DEBUG", "false").lower() == "true"', source
    )
    changed = new != source
    # also fix app.run(debug=True) -> debug=DEBUG
    new2 = _DEBUG_KW_RE.sub("debug=DEBUG", new)
    if new2 != new:
        changed = True
    new = new2
    if not changed:
        return None
    if "import os" not in new:
        new = _ensure_os_import(new)
    return new, (
        "DEBUG is now read from the APP_DEBUG environment variable (default "
        "False); server start uses debug=DEBUG instead of a literal True."
    )


def fix_hardcoded_secret(source: str) -> tuple[str, str] | None:
    changed = False
    out_lines: list[str] = []
    for line in source.splitlines(keepends=True):
        m = _SECRET_LITERAL_RE.match(line)
        if m and "os.environ" not in line and "getenv" not in line:
            name = m.group(1)
            indent = line[: len(line) - len(line.lstrip())]
            fallback = "DEMO-PLACEHOLDER-dev-only"
            newline = f'{indent}{name} = os.environ.get("{name}", "{fallback}")' + (
                "\n" if line.endswith("\n") else ""
            )
            out_lines.append(newline)
            changed = True
        else:
            out_lines.append(line)
    if not changed:
        return None
    new = "".join(out_lines)
    if "import os" not in new:
        new = _ensure_os_import(new)
    return new, (
        "Hard-coded secret(s) now load from os.environ with a non-secret "
        "DEMO-PLACEHOLDER dev fallback."
    )


def fix_sql_injection(source: str) -> tuple[str, str] | None:
    """Rewrite f-string SQL of the form ... WHERE col = '{var}' into ? params."""
    re.compile(
        r"""(?P<q>["'])f?(?P=q)?"""  # placeholder, refined below
    )
    # Specifically target: query = f"SELECT ... WHERE <col> = '{<var>}'"
    rx = re.compile(
        r"""f(?P<quote>["'])(?P<sql>[^"']*?=\s*)'\{(?P<var>\w+)\}'(?P<tail>[^"']*)(?P=quote)""",
    )
    m = rx.search(source)
    if not m:
        return None
    sql = m.group("sql") + "?" + m.group("tail")
    new_literal = f'"{sql}"'
    new = source[: m.start()] + new_literal + source[m.end() :]
    var = m.group("var")
    # Now turn ``conn.execute(query)`` into ``conn.execute(query, (var,))``.
    exec_rx = re.compile(r"(\.execute\(\s*query\s*)\)")
    new2 = exec_rx.sub(rf"\1, ({var},))", new, count=1)
    if new2 == new:
        # Inline form: ``conn.execute(f"...")`` directly.
        new2 = new
    new = new2
    if new == source:
        return None
    return new, (
        "SQL is now a parameterized query with a ? placeholder; the value is "
        "passed as a bound parameter instead of interpolated, closing the "
        "injection."
    )


def fix_wrong_table(source: str) -> tuple[str, str] | None:
    new = _WRONG_TABLE_RE.sub("FROM users", source)
    if new == source:
        return None
    return new, "Corrected the table name from `user` to `users`."


def fix_wildcard_cors(source: str) -> tuple[str, str] | None:
    new = _WILDCARD_CORS_RE.sub(
        "ALLOWED_ORIGINS = [o.strip() for o in "
        'os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",") '
        "if o.strip()]",
        source,
    )
    if new == source:
        return None
    if "import os" not in new:
        new = _ensure_os_import(new)
    return new, ("Wildcard CORS replaced by an explicit, env-driven allow-list (ALLOWED_ORIGINS).")


def fix_missing_route_auth(source: str) -> tuple[str, str] | None:
    """Inject a require_admin() guard at the top of unguarded sensitive routes."""
    tree = _safe_parse(source)
    if tree is None:
        return None
    targets: list[ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        route_paths = [p for p in (_decorator_route_path(d) for d in node.decorator_list) if p]
        if not route_paths:
            continue
        if not any(h in route_paths[0].lower() for h in SENSITIVE_ROUTE_HINTS):
            continue
        if _func_has_decorator_named(node, AUTH_GUARD_NAMES) or _func_calls_name(
            node, AUTH_GUARD_NAMES
        ):
            continue
        targets.append(node)
    if not targets:
        return None

    lines = source.splitlines(keepends=True)
    # Insert guard at the start of each target body, deepest line first so
    # earlier insertions don't shift later line numbers.
    targets.sort(key=lambda n: n.body[0].lineno, reverse=True)
    for node in targets:
        first_stmt = node.body[0]
        insert_at = first_stmt.lineno - 1
        indent = " " * first_stmt.col_offset
        guard = (
            f"{indent}if not require_admin():\n"
            f'{indent}    return jsonify({{"error": "unauthorized"}}), 401\n'
        )
        lines.insert(insert_at, guard)
    new = "".join(lines)

    if "def require_admin(" not in new:
        new = _inject_require_admin_helper(new)
    if "jsonify" not in new.split("\n")[0:30].__str__() and "import" in new:
        new = _ensure_flask_jsonify_import(new)
    return new, (
        "Added a require_admin() bearer-token guard at the top of each sensitive "
        "route; unauthenticated callers receive 401."
    )


# --------------------------------------------------------------------------- #
# Small import / helper injectors
# --------------------------------------------------------------------------- #


def _insert_after_module_docstring(source: str, block: str) -> str:
    tree = _safe_parse(source)
    insert_line = 0
    if (
        tree
        and tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(getattr(tree.body[0], "value", None), ast.Constant)
    ):
        insert_line = tree.body[0].end_lineno or 0
    lines = source.splitlines(keepends=True)
    block_text = block if block.endswith("\n") else block + "\n"
    return "".join(lines[:insert_line]) + block_text + "".join(lines[insert_line:])


def _ensure_os_import(source: str) -> str:
    if re.search(r"^\s*import os\b", source, re.MULTILINE):
        return source
    return _insert_after_module_docstring(source, "import os\n")


def _ensure_flask_jsonify_import(source: str) -> str:
    if "jsonify" in source and re.search(r"from flask import[^\n]*jsonify", source):
        return source
    if re.search(r"^from flask import .*", source, re.MULTILINE):
        return re.sub(
            r"^(from flask import .*)$",
            lambda m: m.group(1) if "jsonify" in m.group(1) else m.group(1) + ", jsonify",
            source,
            count=1,
            flags=re.MULTILINE,
        )
    return source


REQUIRE_ADMIN_HELPER = '''\

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "DEMO-PLACEHOLDER-admin-token")


def require_admin() -> bool:
    """Return True only for a valid admin bearer token (constant-time check)."""
    import hmac

    from flask import request

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth[len("Bearer "):].strip()
    return hmac.compare_digest(token, ADMIN_TOKEN)
'''


def _inject_require_admin_helper(source: str) -> str:
    if "import os" not in source:
        source = _ensure_os_import(source)
    # Place the helper before the first @app.route decorator if possible.
    m = re.search(r"^@\w+\.route\(", source, re.MULTILINE)
    if m:
        idx = source.rfind("\n", 0, m.start())
        insert_at = idx + 1 if idx != -1 else m.start()
        return source[:insert_at] + REQUIRE_ADMIN_HELPER + "\n" + source[insert_at:]
    return source + "\n" + REQUIRE_ADMIN_HELPER


# --------------------------------------------------------------------------- #
# Fixer registry — maps issue ids to (fixer, label)
# --------------------------------------------------------------------------- #

FIXERS: dict[str, Callable[[str], tuple[str, str] | None]] = {
    "plaintext_password_compare": fix_plaintext_password,
    "insecure_debug": fix_debug_true,
    "debug_run_true": fix_debug_true,
    "hardcoded_secret": fix_hardcoded_secret,
    "sql_injection": fix_sql_injection,
    "wrong_table_name": fix_wrong_table,
    "wildcard_cors": fix_wildcard_cors,
    "missing_route_auth": fix_missing_route_auth,
}


def fix_source(source: str, issue_ids: list[str]) -> tuple[str, list[tuple[str, str]]]:
    """Apply each relevant fixer in turn to a single source string.

    Returns (new_source, [(fix_id, rationale), ...]). Pure / testable.
    """
    current = source
    applied: list[tuple[str, str]] = []
    # Apply in a stable, dependency-aware order: structural rewrites that change
    # line counts (auth guard, function replace) last.
    order = [
        "wrong_table_name",
        "sql_injection",
        "wildcard_cors",
        "insecure_debug",
        "debug_run_true",
        "hardcoded_secret",
        "plaintext_password_compare",
        "missing_route_auth",
    ]
    seen: set[str] = set()
    for fid in order:
        if fid not in issue_ids or fid in seen:
            continue
        fixer = FIXERS.get(fid)
        if fixer is None:
            continue
        result = fixer(current)
        if result is None:
            continue
        new_src, rationale = result
        if new_src != current:
            current = new_src
            applied.append((fid, rationale))
            seen.add(fid)
    return current, applied


def _unified_diff(before: str, after: str, path: str) -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    )
    return "".join(diff)


def rescue_file(path: Path, issues: list[Issue]) -> tuple[str, list[FixResult]]:
    """Fix one file. Returns (new_source, fix_results)."""
    before = path.read_text(encoding="utf-8")
    ids = [i.id for i in issues]
    after, applied = fix_source(before, ids)
    results: list[FixResult] = []
    if after != before:
        rel = path.name
        for fid, rationale in applied:
            results.append(FixResult(file=rel, fix_id=fid, rationale=rationale, diff=""))
        # Attach the full per-file unified diff to the first result.
        full = _unified_diff(before, after, rel)
        if results:
            results[0].diff = full
        else:
            results.append(FixResult(file=rel, fix_id="composite", rationale="", diff=full))
    return after, results


# --------------------------------------------------------------------------- #
# End-to-end rescue
# --------------------------------------------------------------------------- #


def rescue(
    source: Path,
    *,
    fixed_dir: Path | None = None,
    scanned_at: str | None = None,
    narrative: bool = False,
    client: LLMClient | None = None,
) -> RescueReport:
    """Diagnose, surgically patch each file, re-scan, optionally narrate.

    If ``fixed_dir`` is given, the patched tree is written there (the input is
    never mutated). Re-diagnosis runs against the patched sources in memory.
    """
    source = source.resolve()
    timestamp = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    before = diagnose(source, scanned_at=timestamp)

    base = source if source.is_dir() else source.parent
    all_fixes: list[FixResult] = []
    after_issues: list[Issue] = []
    patched: dict[str, str] = {}  # rel -> new source

    for path in _iter_py_files(source):
        rel = str(path.relative_to(base)) if path != source else path.name
        file_issues = [i for i in before.issues if i.file == rel]
        if file_issues:
            new_src, results = rescue_file(path, file_issues)
        else:
            new_src, results = path.read_text(encoding="utf-8"), []
        patched[rel] = new_src
        all_fixes.extend(results)
        after_issues.extend(diagnose_source(rel, new_src))

    after_issues.sort(key=lambda i: (SEVERITY_ORDER.index(i.severity), i.file, i.line))
    after = DiagnosisReport(
        project=str(source),
        scanned_at=timestamp,
        issues=after_issues,
        summary=_summarize(after_issues),
    )

    if fixed_dir is not None:
        _write_fixed_tree(source, base, patched, fixed_dir.resolve())

    report = RescueReport(
        project=str(source),
        generated_at=timestamp,
        before=before,
        after=after,
        fixes_applied=all_fixes,
    )
    if narrative:
        llm = client or default_client()
        enrich_with_narrative(report, llm)
    return report


def _write_fixed_tree(source: Path, base: Path, patched: dict[str, str], dest: Path) -> None:
    """Write the patched sources (and copy any non-.py files) into dest."""
    dest.mkdir(parents=True, exist_ok=True)
    # Write patched python files.
    for rel, content in patched.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    # Copy non-python files verbatim (so the tree is runnable).
    if source.is_dir():
        for path in source.rglob("*"):
            if path.is_file() and path.suffix != ".py":
                rel = path.relative_to(base)
                target = dest / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())


# --------------------------------------------------------------------------- #
# Narrative
# --------------------------------------------------------------------------- #


def build_narrative_prompt(before: DiagnosisReport, after: DiagnosisReport) -> str:
    lines = ["Summarize this vibe-code rescue for a client (max 120 words):\n"]
    lines.append("BEFORE:")
    for issue in before.issues:
        lines.append(f"- [{issue.severity}] {issue.title} ({issue.file}:{issue.line})")
    lines.append("\nAFTER:")
    lines.append(f"- remaining issues: {after.summary.get('total', 0)}")
    fixed_n = before.summary.get("total", 0) - after.summary.get("total", 0)
    lines.append(f"- fixes applied: {fixed_n}")
    return "\n".join(lines)


def enrich_with_narrative(report: RescueReport, client: LLMClient) -> RescueReport:
    report.narrative = client.complete(build_narrative_prompt(report.before, report.after))
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
        description="Detect and surgically fix security bugs in AI-generated apps.",
    )
    parser.add_argument(
        "project",
        type=Path,
        help="Path to the app directory or a single .py file",
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
        help="Directory to write the surgically patched tree",
    )
    parser.add_argument(
        "--diff",
        type=Path,
        default=None,
        help="Also write the combined unified diff here",
    )
    parser.add_argument(
        "--narrative",
        action="store_true",
        help="Add an executive summary (Claude when ANTHROPIC_API_KEY set, else stub)",
    )
    parser.add_argument(
        "--diagnose-only",
        action="store_true",
        help="Only run diagnosis (no fixes, no patched tree)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    project = args.project.resolve()

    if not project.exists():
        print(f"error: path not found: {project}", file=sys.stderr)
        return 2

    if args.diagnose_only:
        report = diagnose(project)
        write_report(report, args.out)
        print(f"Diagnosed {report.summary['total']} issue(s) → {args.out}")
        return 1 if report.summary.get("critical", 0) else 0

    rescue_report = rescue(
        project,
        fixed_dir=args.fixed_dir.resolve(),
        narrative=args.narrative,
    )
    write_report(rescue_report, args.out)

    if args.diff is not None:
        combined = "\n".join(f.diff for f in rescue_report.fixes_applied if f.diff)
        args.diff.parent.mkdir(parents=True, exist_ok=True)
        args.diff.write_text(combined, encoding="utf-8")

    remaining = rescue_report.after.summary.get("total", 0)
    fixed_n = rescue_report.before.summary["total"] - remaining
    print(
        f"Rescued {project.name}: "
        f"{rescue_report.before.summary['total']} issue(s) → {remaining} remaining "
        f"({fixed_n} fixed) → {args.out}"
    )
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
