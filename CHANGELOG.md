# Changelog

All notable changes to PromptShield are documented here.

## [0.6.0] – Multi-tenancy, dashboard, packaging hardening

### Added

- Multi-tenancy: `Organization`, `ApiKey`, `UsageRecord`
- Admin API: create organizations, manage API keys with granular permissions
- Usage tracking (analyses / blocks / secrets per org-month)
- Automatic tenancy seed for Default organization
- Bundled `resources/plugins` and `resources/config` in the package wheel
- Admin dashboard (Jinja2 + Chart.js): overview, compliance, analyses, audit
- Dashboard JSON API (`/api/v1/dashboard/*`)
- Optional `PROMPTSHIELD_DASHBOARD_KEY`
- Monthly HTML report export
- CLI: `promptshield dashboard`

### Fixed

- CLI human output no longer prints full secrets/PII (preview/token only)
- Explainer no longer uses raw `matched_text` for risk factors

### Changed

- Project version set to **0.6.0**
- License aligned to **Apache-2.0**

## [0.5.1] – Dashboard (Milestone 5 historical)

- Admin dashboard (Jinja2 + Chart.js): overview, compliance, analyses, audit
- Dashboard JSON API (`/api/v1/dashboard/*`)
- Optional `PROMPTSHIELD_DASHBOARD_KEY`
- Monthly HTML report export
- CLI: `promptshield dashboard`

## [0.5.0] – Persistence (Milestone 4B)

- SQLAlchemy models: Analysis, FindingRecord, AuditEvent
- AES-256-GCM optional prompt encryption
- Audit endpoints: `/analyses`, `/stats`, `/events`
- Retention policy + `promptshield cleanup`

## [0.4.0] – Enterprise API (Milestone 4A)

- `PromptShieldService` shared by CLI and API
- FastAPI REST: `/analyze`, `/sanitize`, `/health`
- Docker / docker-compose
- Python `PromptShieldClient`

## [0.3.0] – Intelligence (Milestone 3C)

- Prompt classifier (strategy pattern)
- Risk explainer with policy priority
- CLI/API `--explain` / `intelligence` JSON

## [0.2.0] – Policy engine (Milestone 3B)

- YAML policies (`block` / `warn` / `allow`)
- Priority resolution and CLI integration

## [0.1.x] – Foundation (Milestones 1–3A)

- Plugin detectors and analysis pipeline
- Risk scoring and breakdown
- Sanitizer
- Context detector
- Compliance framework mapping
- CI-friendly exit codes and JSON reports

## [0.1.0] – Initial foundation

- Core package structure, Secret/Keyword detectors, interactive CLI
