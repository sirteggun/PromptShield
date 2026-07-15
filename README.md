# PromptShield – Open-Source AI Firewall

**Stop accidental leaks of secrets, PII, and proprietary code to ChatGPT, Claude, Copilot, and other LLMs.**

```text
Before: Developer → LLM → 💥 secret leaked
After:  Developer → PromptShield → ✅ Safe AI usage
```

[![CI](https://github.com/sirteggun/PromptShield/actions/workflows/ci.yml/badge.svg)](https://github.com/sirteggun/PromptShield/actions/workflows/ci.yml)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](https://github.com/sirteggun/PromptShield/blob/main/LICENSE)
[![Tests](https://img.shields.io/badge/tests-147%20passing-brightgreen.svg)](https://github.com/sirteggun/PromptShield/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.6.0-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)]()

## The problem

AI assistants are becoming part of every engineering workflow.

But developers are accidentally sending:

- AWS credentials
- customer emails
- internal URLs
- proprietary code
- production incidents

to external LLM providers.

PromptShield acts as a security gateway before your prompt reaches an AI model.

```text
Developer
    |
    v
PromptShield
    |
    +--> Block secrets
    +--> Redact PII
    +--> Audit usage
    |
    v
ChatGPT / Claude / Copilot
```

## Why PromptShield?

Every day, developers accidentally paste API keys, customer data, and internal URLs into AI prompts. Existing tools scan code **after** it's written. PromptShield protects the prompt **before** it's sent.

## Features

- 🔍 **9 security detectors** — AWS keys, JWT, GitHub tokens, private keys, email, private IPs, internal URLs, context keywords
- 🛡️ **Policy engine (YAML)** — `block` / `warn` / `allow` with priorities
- 🧹 **Smart sanitization** — replacement tokens, overlap-aware
- 🧠 **Prompt intelligence** — content classification + natural-language risk explanation
- 📊 **Enterprise dashboard** — compliance scores, trends, audit timeline
- 🏢 **Multi-tenant ready** — organizations, granular API keys, usage tracking
- 🐳 **Docker & REST API** — FastAPI, OpenAPI `/docs`, CI-friendly exit codes

## Quickstart

```bash
pip install -e ".[dev]"   # from source
# or: pip install promptshield-security  (when published)

echo "My AWS key is AKIA1234567890ABCDEF" | promptshield --json -y
# → policy_decision.action: block, exit code 2
```

### API

```bash
python -m promptshield serve
# Swagger: http://127.0.0.1:8000/docs

curl -s -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PROMPTSHIELD_API_KEY" \
  -d '{"prompt":"AKIA1234567890ABCDEF","explain":true}'
```

### Dashboard

```bash
python -m promptshield dashboard
# → http://127.0.0.1:8000/dashboard
```

Optional: `PROMPTSHIELD_DASHBOARD_KEY` for dashboard auth.

### Multi-tenant admin

```bash
# Create organization (requires admin:create_organization)
curl -s -X POST http://127.0.0.1:8000/api/v1/admin/organizations \
  -H "X-API-Key: $MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp"}'
# → returns api_key once with full permissions
```

## Architecture

```text
Prompt → Detectors → Findings → Risk score
                   → Policy engine → block / warn / allow
                   → Sanitizer (optional)
                   → Classifier + Explainer (--explain)
                   → Persistence + usage (API, optional)
```

CLI and HTTP share `PromptShieldService`. Persistence and multi-tenancy are **optional** for CLI.

## Configuration (env)

| Variable | Purpose |
|---|---|
| `PROMPTSHIELD_API_KEY` | Comma-separated API keys (seeded into Default org) |
| `PROMPTSHIELD_ENV` | `development` / `production` |
| `DATABASE_URL` | SQLite (default) or PostgreSQL |
| `PROMPTSHIELD_ENCRYPTION_KEY` | 64-hex AES-256 key for encrypted prompts |
| `PROMPTSHIELD_RETENTION_DAYS` | Audit retention (default 90) |
| `PROMPTSHIELD_DASHBOARD_KEY` | Protect HTML dashboard |
| `PROMPTSHIELD_PERSISTENCE` | `1`/`0` for API persistence |

## Documentation

- **CLI** — `promptshield --help`, `serve`, `dashboard`, `cleanup`
- **API** — interactive OpenAPI at `/docs`
- **Dashboard** — `/dashboard` (overview, compliance, analyses, audit)
- **Contributing** — see [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog** — see [CHANGELOG.md](CHANGELOG.md)

## License

Licensed under the **Apache License 2.0**.
