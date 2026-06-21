# Vibe Code Rescue

A small, production-minded Python tool that **diagnoses, patches, and reports**
on common failures in AI-generated (“vibe-coded”) web apps — broken data access,
missing auth, insecure configuration, and logic bugs.

It is the reusable delivery template for the freelance gig: *“fix and secure this
app an AI assistant generated.”*

---

## What it does

Given a miniature Flask-style project (the bundled `sample_input/broken_app/`),
the tool:

1. **Diagnoses** — static analysis finds seven realistic issues: SQL injection,
   wrong table name, missing admin auth, debug mode left on, hard-coded secret,
   wildcard CORS, and inverted password verification.
2. **Patches** — writes a hardened `output/fixed_app/` with parameterized SQL,
   bearer-token admin guard, env-driven secrets, and corrected login logic.
3. **Validates** — AST + rule checks confirm the rescued app is syntactically
   valid and free of the original bug classes (offline, no server required).
4. **Reports** — JSON before/after summary with severities, line numbers, and
   remediation text; optional executive narrative via Claude or `StubClient`.

**Business value:** turn a risky AI prototype into something you can ship — with
an auditable report suitable for PRs, tickets, or client handoff.

---

## How to run

```bash
pip install -r requirements.txt

# Full rescue: diagnose → patch → validate → report
python vibe_code_rescue.py sample_input/broken_app --out output/sample_report.json

# Diagnosis only
python vibe_code_rescue.py sample_input/broken_app --diagnose-only --out output/diagnosis.json

# Add executive summary (optional; uses Claude when ANTHROPIC_API_KEY is set)
export ANTHROPIC_API_KEY="sk-ant-..."
python vibe_code_rescue.py sample_input/broken_app --narrative --out output/sample_report.json
```

Without `ANTHROPIC_API_KEY`, `--narrative` uses `StubClient` — useful for demos
and CI.

### Run the tests (offline — no API key or network)

```bash
pip install -r requirements.txt
python -m pytest -q
```

---

## Acceptance / "done"

A run is considered correct when:

- `python -m pytest -q` passes offline using fixtures and `StubClient`.
- `python vibe_code_rescue.py sample_input/broken_app` writes valid JSON and a
  patched tree under `output/fixed_app/`.
- All seven bundled bugs are detected; the fixed app reports zero remaining issues.
- No real credentials appear in the repo — placeholders use `DEMO-PLACEHOLDER`.

The committed `output/sample_report.json` is the exact result of rescuing
`sample_input/broken_app/` with a fixed timestamp.

---

## Project layout

```
vibe-code-rescue/
├── vibe_code_rescue.py          # diagnose, patch, validate, CLI
├── requirements.txt             # anthropic + pytest
├── sample_input/
│   └── broken_app/              # intentional vibe-coding bugs
│       ├── app.py
│       ├── config.py
│       └── db.py
├── test_vibe_code_rescue.py     # offline pytest suite
├── output/
│   ├── sample_report.json       # committed demo report
│   └── fixed_app/               # committed patched sources
└── README.md
```

---

## Architecture notes

- **Rule engine** — regex and structural checks with stable IDs, severities, and
  fix guidance; no network or runtime server needed for tests.
- **`apply_fixes`** — deterministic templates (not LLM-generated) so CI stays
  reproducible; optional Claude narrative is summary-only.
- **`validate_fixed`** — AST parse + semantic guards before declaring rescue complete.
- **Exit code** — returns `1` when critical issues remain after rescue (CI-friendly).

---

## Sample input → output

**Input** (`sample_input/broken_app/`): a tiny Flask-style app with SQL injection,
an unauthenticated admin route, insecure settings, and inverted login logic.

**Output** (`output/sample_report.json`): JSON with `before`/`after` issue counts,
per-finding detail, `fixes_applied`, and optional `narrative`.

**Patched app** (`output/fixed_app/`): production-minded defaults ready for review.

---

Built by [clira](https://clira.dev) — AI delivery for teams that need production-quality code, not demos.
