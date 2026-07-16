# Contributing to PromptShield

Thanks for helping build an open-source AI prompt firewall.

## Development setup

```bash
git clone https://github.com/sirteggun/PromptShield.git
cd promptshield
python -m venv .venv
# Windows: .venv\Scripts\activate
# Unix: source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest -q
```

Use an in-memory SQLite URL in tests (`DATABASE_URL=sqlite:///:memory:`). Do not commit secrets.

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
- Format and type-check when practical (`mypy` optional in CI).

## Pull requests

1. Branch from `main`.
2. Add/adjust tests so `pytest` stays green.
3. Update `CHANGELOG.md` under **Unreleased** if user-facing.
4. Describe *why* in the PR body; link issues when relevant.

## Reporting security issues

Do not open public issues for vulnerabilities that could leak secrets. Prefer a private security advisory or email maintainers.

## Code of conduct

Be respectful. We welcome contributors of all backgrounds.
