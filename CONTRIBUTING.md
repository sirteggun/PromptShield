# Contributing to PromptShield

Thanks for helping build PromptShield, an open-source security gateway for safe AI usage.

## Development setup

```bash
git clone https://github.com/sirteggun/PromptShield.git
cd PromptShield
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest -q
```

Tests use in-memory SQLite by default (`DATABASE_URL=sqlite:///:memory:` when configured). You do not need an external database for the standard suite. Do not commit secrets.

## Project layout

| Path | Role |
|---|---|
| `src/promptshield/` | Core library, service, CLI |
| `src/promptshield/api/` | FastAPI REST API |
| `src/promptshield/dashboard/` | Admin HTML UI |
| `src/promptshield/persistence/` | SQLAlchemy models, tenancy, usage |
| `plugins/` | Detector plugins (auto-loaded) |
| `config/` | `rules.yaml`, `policies.yaml` |
| `tests/` | pytest suite |

## Coding guidelines

- Keep public APIs stable: `BaseDetector`, `AnalysisPipeline`, `Finding`, `RiskScoringEngine`, `PolicyEngine`.
- Prefer incremental changes; add tests with every feature.
- Never log or persist full secrets in plaintext.
- Use Google-style docstrings on public modules.
- Before opening a PR, run:

```bash
ruff check .
ruff format --check .
mypy src --strict --ignore-missing-imports
```

## Pull requests

1. Branch from `main`.
2. Add/adjust tests so `pytest` stays green.
3. Update `CHANGELOG.md` under **Unreleased** if user-facing.
4. Describe *why* in the PR body; link issues when relevant.

## Reporting security issues

Do not open public issues for security vulnerabilities (including issues that could lead to secret leaks).

Report privately via [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories) on this repository so maintainers can assess and fix the issue before disclosure.

## Code of conduct

Be respectful. We welcome contributors of all backgrounds.
