# Security Policy

VulnForge is an early-stage security automation prototype and **must not be treated as a complete security control**.

## Reporting vulnerabilities

Please do not publish exploit details or secrets in a public GitHub issue. Instead, use GitHub's **Report a vulnerability** / private security advisory flow on this repository when enabled, or contact the repository maintainer through an agreed private channel.

## Supported releases

Only the latest development version receives security fixes. GitHub App keys, admin tokens and webhook signing secrets must never be committed to this repository.

## Limitations

Server-side source access and outbound OSV package queries default to disabled. Managed source access requires explicit consent; public package queries require separate metadata consent and an exact package allowlist. Operator runner reports remain quarantined and never authorize scans or fixes. See the [privacy architecture](docs/PRIVACY_ARCHITECTURE_TR.md) for data boundaries and remaining controls.

GitHub login/session code is locally tested but awaits real provider acceptance. Verified runner ingestion and complete worker/queue/cache tenant isolation are not yet implemented. PostgreSQL customer queries now use FORCE RLS, session proof and a separate unprivileged DB connection; customer preview rejects privileged/owner runtime accounts. See the [database boundary](docs/DATABASE_ISOLATION_TR.md). A local-only organization API preview enforces role and query scope, with its customer gate disabled by default; it cannot be enabled for public hostnames. See the [access boundary](docs/ORGANIZATION_ACCESS_TR.md). See the [login boundary](docs/GITHUB_LOGIN_TR.md). Identity tables and PostgreSQL support do not make this safe to expose as a shared customer service. The separate `/operator` console and named operator credentials provide audited global operator access; customer sessions cannot authorize these APIs. Retention and backup-deletion targets are documented but not automated.

Repository remediation opt-in is organization-admin controlled and connection-bound. Worker PR publication is closed until isolated validation and SHA/diff-bound approval exist; bound worker tokens request read-only contents/pull_requests permissions. Merge and non-draft write routes are rejected. No auto-merge, no compatibility guarantees, and no CI validation of candidate patches is performed by the agent. Live GitHub/OSV, deployment and production security acceptance remain outstanding.

The offline customer scanner and composite Action are locally tested; immutable distribution, production trusted OIDC ingestion and live runner acceptance remain pending. Scanner output omits source and uses path pseudonyms; pseudonyms and package identities can still be sensitive. See [runner boundaries](docs/RUNNER_TR.md). Catchable Action interruption cleans temporary metadata; host failure requires ephemeral-runner destruction or administrator retention controls.

The loopback-only OIDC preview checks fixed issuer/audience, RS256/JWKS, immutable IDs, protected branch, pinned reusable workflow, current metadata-only App identity, and transactional replay/conflict barriers. Verified receipts remain quarantined and cannot become scan baselines. Production runner ingestion, live provider acceptance, workflow distribution and full worker isolation remain closed/pending. [Protocol boundary](docs/RUNNER_IDENTITY_TR.md).
