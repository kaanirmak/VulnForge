# VulnForge 0.3.0 — GitHub security monitoring

FastAPI webhook intake, a durable SQLite/PostgreSQL queue, a separate worker, basic static rules, policy-gated OSV checks, snapshot evidence and an operator dashboard. The full target architecture in the technical design is **not implemented**. See the [Turkish requirements assessment](docs/REQUIREMENTS_COMPLIANCE_TR.md) and [tracked tasks](docs/TASKS_TR.md) for completed work and remaining gaps.

## Privacy defaults and readiness

The default `SCAN_MODE=customer_runner` blocks server-side GitHub source access. `INTELLIGENCE_MODE=disabled` blocks outbound OSV queries. An offline customer CLI and composite Action are implemented and tested locally; immutable distribution and live Action acceptance remain pending. Production verified workflow ingestion and complete worker tenant isolation remain pending. GitHub login/session code exists but live provider acceptance is pending: **the default installation does not yet provide end-to-end customer scanning**. Operator report uploads use a strict, versioned metadata schema and a separate token; they remain quarantined and cannot become trusted scans or inventory.

Existing server-side scanning requires explicit managed-mode consent. Public OSV additionally requires metadata-sharing consent and an exact package allowlist; private package denials override it. See the [privacy architecture](docs/PRIVACY_ARCHITECTURE_TR.md), [retention targets](docs/DATA_RETENTION_TR.md), [technical privacy notice](docs/PRIVACY_NOTICE_DRAFT_TR.md) and [license assessment](docs/LICENSE_REVIEW_TR.md). These controls do not make this prototype ready for a multi-customer service.

A separate organization API now applies per-role access and SQL organization scope for repositories, findings, scans, impacts/recommendations and exports. `CUSTOMER_API_PREVIEW=false` by default; enabling this preview requires explicitly configured loopback development auth and is rejected for public hostnames. PostgreSQL additionally uses FORCE RLS and separate non-owner runtime connections. Production worker isolation and live acceptance remain pending. See the [access guide](docs/ORGANIZATION_ACCESS_TR.md) and [database isolation runbook](docs/DATABASE_ISOLATION_TR.md).

## Current capabilities

- HMAC-SHA256 webhook verification, streaming payload limit and atomic delivery/job deduplication. Failed enqueue rolls back acceptance so redelivery can retry.
- Push commit enumeration through Compare; initial pushes enumerate history from the immutable SHA. Enumeration is bounded at 2,000 commits and fails visibly when incomplete.
- Pull request events scan the complete paginated PR file list, check HEAD before/after collection and run a separate dependency audit at the PR SHA. PR results do not replace default-branch dependency inventory.
- Basic Python AST / JS regex rules and masked credential-pattern evidence. Repository code is never executed.
- Six dependency manifests: requirements.txt, poetry.lock, package-lock.json, Cargo.lock, go.mod, composer.lock. OSV package/version queries, continuation pages and refreshed advisory details; optional CISA KEV enrichment.
- Persistent scans with immutable SHA, manifest SHA-256, dependencies, findings, coverage issues and complete/incomplete/failed states. An incomplete scan cannot close old dependency findings.
- CycloneDX 1.6 SBOM and SARIF 2.1.0 JSON exports tied to a scan. Incomplete inventory remains explicitly incomplete in exports.
- Optional GitHub Checks and batched line annotations. Incomplete analysis reports `action_required`; complete scans with high/critical findings report `failure`.
- Admin triage with reason, expiring single-finding suppression and observation/triage/expiry audit events. Active suppression survives rescans.
- Dashboard with coverage, export downloads and total counters independent of list limits. Admin token stays in memory.

## New vulnerabilities and project update recommendations

With managed scanning and an intelligence policy enabled, signed advisory events and scheduled OSV audits persist advisory-to-project impacts and upgrade suggestions for human review. The dashboard's **Yeni açıklar ve etkilenen projeler** section filters by repository and CVE/GHSA/OSV identifier, shows package/current/target versions and provides a manual refresh action. The worker schedules checks every 15 minutes (`SCAN_INTERVAL_SECONDS=900`); source or metadata policy failures remain visible failures rather than clean scans. This scheduled path cannot yet consume trusted customer-runner inventory.

Targets are checked against all current OSV advisories and supported new GitHub vulnerability ranges before being recommended. A candidate project is not automatically affected; missing data stays under investigation. No fix, unsupported versions, failed verification and withdrawn advisories have explicit states. Publication/compatibility/tests remain unverified, and suggestions do not apply updates. See the [Turkish feature guide](docs/THREAT_INTELLIGENCE_TR.md).

New authenticated endpoints: `GET /api/v1/advisories`, `GET /api/v1/impacts` (repository/advisory/state filters and cursor pagination), and `POST /api/v1/intelligence/refresh` (optional repository).

## Remediation safety change

`ENABLE_AUTO_PR` defaults to false. Repository-specific opt-in now requires organization-admin approval and exact package/file allowlists, bound to the current connection. **Worker PR publication remains closed even with opt-in** until isolated resolver/build/test and SHA+diff-bound human approval exist. Bound worker tokens request contents/pull_requests read only; merge and non-draft write operations are rejected. There is no auto-merge. See the [policy and account guide](docs/ACCOUNT_OPERATIONS_TR.md).

## Run locally

Requires Python **3.11 or newer**. Default local inspection needs no GitHub private key. Managed scanning additionally needs an authorized GitHub App installation.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,postgres]'
cp .env.example .env
# Set independent random WEBHOOK_SECRET and ADMIN_TOKEN values.
set -a; source .env; set +a
python -m pytest -q
uvicorn vulnforge.api:app --host 127.0.0.1 --port 8000
# Second terminal, same environment:
python -m vulnforge.worker
```

Alternatively, configure `.env` and run `docker compose up --build -d`. Default Compose mounts no App key and enforces customer-runner mode. Its image includes the PostgreSQL driver; Docker image/build acceptance remains untested. The dashboard binds to localhost at port 8000. Put HTML/API behind an identity-aware HTTPS proxy before internet exposure; the webhook uses its own signature authentication.

SQLite and PostgreSQL now use checksummed versioned migrations. For PostgreSQL customer preview, provision separate migration/operator/customer accounts; set `DATABASE_AUTO_MIGRATE=false` in runtime and `CUSTOMER_DATABASE_URL` to the restricted connection. The customer API rejects a migration owner or superuser. Follow the [account setup](docs/DATABASE_ISOLATION_TR.md) before enabling even local PostgreSQL preview. `DATABASE_URL` selects PostgreSQL and takes precedence over `DATABASE_PATH`. Existing supported SQLite databases receive additive migrations without deleting records. Back up before upgrading; stop writers before transferring to an empty PostgreSQL database. Follow the [migration runbook](docs/DATABASE_MIGRATION_TR.md). A [user/org/membership/ownership persistence model](docs/IDENTITY_MODEL_TR.md) is present; it supports the new account session, but does not yet authorize customer project data or isolate legacy APIs.

## GitHub account login

The root redirects to `/account`; the global operator console is at `/operator`. Named `OPERATOR_CREDENTIALS` replace the legacy shared operator key and audit authenticated access without recording credentials or request values. Customer sessions remain separate. See the [operator guide](docs/ACCOUNT_OPERATIONS_TR.md).

The `/account` page supports GitHub OAuth with browser-bound single-use state, S256 PKCE and opaque local sessions. It is disabled until `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` and a fixed HTTPS `PUBLIC_ORIGIN` are configured together. Customer sessions do not grant operator API access. Local protocol and two-org data access tests pass; real App callback acceptance remains outstanding. Follow the [login guide](docs/GITHUB_LOGIN_TR.md); never share the client secret in chat or issues.

## Managed scanning opt-in

For a controlled operator deployment only, set:

```dotenv
SCAN_MODE=managed
ALLOW_MANAGED_SOURCE_ACCESS=true
MANAGED_SCAN_CONSENT_ID=owner-approval-2026-10-27
GITHUB_APP_ID=<your-managed-app-id>
GITHUB_PRIVATE_KEY_PATH=./private-key.pem
INTELLIGENCE_MODE=public_osv
ALLOW_EXTERNAL_PACKAGE_METADATA=true
OSV_ALLOWED_PACKAGES=PyPI:requests,npm:lodash
PRIVATE_PACKAGE_PATTERNS=PyPI:company-*,npm:@company/*
```

Replace example packages with the exact approved inventory. An unapproved/private package blocks the whole query batch before transmission. The private HTTPS OSV client contract uses `private_osv`; queued private scans currently fail closed until private advisory namespaces are implemented. Network isolation must be provided separately. Keep `ENABLE_AUTO_PR=false`. With Compose, use `docker compose -f docker-compose.yml -f docker-compose.managed.yml up --build -d`; only the worker receives the key. See the [Turkish setup guide](BASLANGIC_TR.md).

## Managed GitHub App setup

1. Set the webhook URL to `https://YOUR-DOMAIN/github/webhook` and use `WEBHOOK_SECRET`.
2. Grant **Contents: read**, **Metadata: read**, **Pull requests: read**, and **Dependabot alerts: read** where available.
3. Subscribe to `push`, `pull_request`, `installation`, `installation_repositories`, `dependabot_alert`, `security_advisory`.
4. Optional: grant **Checks: write** and set `ENABLE_CHECKS=true`.
5. Download the private key and set `GITHUB_PRIVATE_KEY_PATH`. Do not commit credentials.
6. Set branch protection and required checks in the monitored repository. VulnForge does not configure protection or bypass review.

This permission set belongs to the managed scanner. The customer-runner metadata identity preview rejects installations with permissions beyond Metadata read. Separate App registrations and the verified onboarding flow remain VF-021–029; changing an environment flag cannot remove permissions already granted to an existing GitHub App.

## API

`GET /health` and the dashboard shell at `/` are public. Existing data/mutation endpoints require `Authorization: Bearer ADMIN_TOKEN`. The operator-only report endpoint instead requires a distinct `OPERATOR_REPORT_TOKEN`; it is disabled while unset.

| Endpoint | Purpose |
|---|---|
| `GET /api/repositories`, `/api/jobs`, `/api/findings` | Existing repository/job/finding lists |
| `GET /api/dependencies`, `/api/remediations` | Last complete default-branch inventory / prior PR records |
| `POST /api/rescan?repo=ORG/REPO` | Queue default-branch dependency audit |
| `GET /api/scans?repo=ORG/REPO` | Recent scans and coverage |
| `GET /api/v1/scans/{id}` | Snapshot evidence and findings |
| `GET /api/v1/scans/{id}/sarif` | SARIF export |
| `GET /api/v1/sbom/{id}` | CycloneDX export for dependency scans |
| `GET /api/v1/findings` | repo/status/severity filters, limit ≤100, integer cursor |
| `PATCH /api/v1/findings/{id}/triage` | status, reason and suppression expiry |
| `GET /api/v1/audit/events` | Recent finding history |
| `GET /api/v1/overview` | Total counters |
| `GET /api/v1/me` | Account identity only; separate session cookie, no operator data access |
| `GET /api/v1/privacy` | Source/metadata policy and explicit customer/tenant readiness |
| `POST /api/v1/operator/runner-reports` | Strict metadata reports, 1 MB maximum, quarantine only; separate operator token |

The filtered findings response is `{items, next_cursor}`; other legacy lists return bounded arrays. Triage accepts `status` (`open`, `resolved`, `suppressed`) and a reason of at least five characters. Suppression requires `expires_at` as Unix seconds within the next 366 days. Authentication still identifies one admin, not separate tenant users.

## Limits

- This is a small static scanner, not Semgrep/CodeQL/Gitleaks or a full dataflow/reachability analyzer. Unsupported files and parsing limits are reported.
- Pinned requirements do not prove transitive resolution; go.mod is a declaration, not the resolved build list. Local/git dependencies, unsupported manifests and parse/feed errors cannot produce a complete clean audit.
- Stored default-branch inventory is the last **complete** audit. Consult scans and SBOM for current partial evidence. Advisory events conservatively recheck repositories with incomplete/failed inventory.
- No isolated patch validator, npm lock regeneration, live-accepted OAuth/SSO, production worker/queue/cache isolation, GitLab, model integration, notifications, HA or delivery-backfill service. PostgreSQL persistence and identity tables alone do not provide those controls.
- Severity is heuristic. CVSS vectors are retained as evidence; EPSS and reachability remain unknown. KEV enrichment indicates catalog membership, not exploitation of the monitored application.
- The latest local suite passed 301 tests, including real temporary PostgreSQL migration, rollback and concurrent queue/last-admin tests. GitHub/OSV calls remain mocked; live App/Checks acceptance, Docker builds, load tests and production security review remain required. Queue leases/retries provide at-least-once processing, not exactly-once external effects.
- Protect metadata, database volumes and backups appropriately. JSON exports contain repository/package names. Retention targets are documented but TTL/backup deletion automation is pending. The dashboard does not persist tokens in browser storage.

## Integration references

- [GitHub webhook verification](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [GitHub Checks API](https://docs.github.com/en/rest/checks/runs)
- [OSV query and pagination](https://google.github.io/osv.dev/post-v1-query/)
- [CycloneDX 1.6 schema](https://cyclonedx.org/schema/bom-1.6.schema.json)

## Offline runner and verification

Install the approved package outside the customer checkout; run `vulnforge-scan` or `python -I -m vulnforge.cli`. No repository code, resolver, subprocess or network request is executed by the scanner. Reports contain only the strict v1 metadata contract and coverage; they do not establish trusted workflow identity. [Runner instructions and Action profiles](docs/RUNNER_TR.md). Workflow templates require the reviewed Action repository/immutable ref and a provisioned runtime before activation.

`python scripts/check.py --postgres` creates a new private Unix-socket PostgreSQL cluster, runs the tests and shuts down/removes that cluster even after test failure. PostgreSQL binaries and the postgres/dev dependencies are prerequisites. It never connects to a shared or production DB. CI uses this path so DB checks are required instead of silently skipped. [Queue lifecycle/dead letters](docs/QUEUE_OPERATIONS_TR.md), [new account operations](docs/ACCOUNT_OPERATIONS_TR.md).

## Identity-verified runner preview

An additional loopback-only preview now verifies GitHub Actions RS256 identity, immutable repository/owner IDs, SHA, protected default branch and a platform-approved commit-pinned reusable workflow. Metadata-only App checks verify the current installation/repository without reading source. Upload receipts have transactional replay/conflict protection and remain `identity_verified_quarantined`; they do not update inventory, findings or scans. The default remains closed. `runner_upload` requires explicit metadata consent and uses short-lived Actions identity, never a shared upload secret. [Protocol, activation prerequisites and remaining live acceptance](docs/RUNNER_IDENTITY_TR.md).
