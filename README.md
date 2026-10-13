# Backend Verification

## Prerequisites

- JDK 21 on `PATH`. The Gradle Wrapper is included; a separate Gradle install is not needed.
- Docker Engine running and reachable by Testcontainers. On Windows, start Docker Desktop with its Linux engine enabled. Verify with `docker info`.
- Network access on the first integration-test run so Docker can pull the PostgreSQL, Kafka, ClamAV, and Mailpit images.

A local PostgreSQL installation or database is not required. The integration tests start disposable PostgreSQL 17, Kafka, ClamAV, and Mailpit containers; PostgreSQL provisions the restricted test role before Flyway applies the checked-in migrations. The tests mock the JWT decoder, so Keycloak and a realm import are not required.

## Run Tests

From PowerShell:

```powershell
Set-Location backend
.\gradlew.bat test
.\gradlew.bat integrationTest
```

`test` runs unit tests without Docker. `integrationTest` runs the PostgreSQL/Testcontainers tests, including real ClamAV EICAR quarantine and Kafka-to-SMTP delivery verified in Mailpit; Docker must be available. `check` does not include `integrationTest`; run that task explicitly when verifying external-service behavior.

If Testcontainers reports that it cannot find a valid Docker environment, start Docker Desktop, confirm `docker info` succeeds, then rerun `integrationTest`. Changing the locally installed PostgreSQL version does not resolve a missing Docker daemon because these tests use their pinned PostgreSQL container.

## Administration, identity, and notifications

- Category administration is available under `/api/v1/admin/categories`, including optimistic-version updates, soft deletion, evidence MIME allow-lists, and localized labels.
- Severity-matrix and SLA policy administration are available at `/api/v1/admin/severity-matrix` and `/api/v1/admin/sla-policies`. Incident legal holds are set or released through `/api/v1/admin/incidents/{id}/legal-hold`.
- A validated Keycloak token can synchronize an active user's application projection. Scheduled Keycloak reconciliation is disabled unless a dedicated least-privilege client is configured; dormant-account disabling is configurable and enabled by default.
- Incident lifecycle notifications are written to a transactional outbox and relayed through Kafka when `incident-platform.notifications.kafka.enabled=true`. The inbox routes (`GET /api/v1/notifications`, `PATCH /api/v1/notifications/{id}/read`) only expose the authenticated user's own in-app notifications. Compose enables Kafka notifications by default.
- Email delivery uses Spring's `JavaMailSender` over configurable standard SMTP. Compose routes email to Mailpit. Email is at-least-once: if the consumer crashes after SMTP acceptance and before recording `SENT`, the retry can produce a duplicate; the stable Message-ID allows downstream identification. In-app records and deduplication are committed in one transaction.
- Broadcast rules match incident creation, severity threshold crossings, escalation, and SLA breach; Reporter and assignee dispatch remains hardcoded and cannot be suppressed by rules. SECURITY_ADMIN can manage rules at `/api/v1/admin/notification-rules`; SECURITY_ADMIN and AUDITOR can read them. Updates use `expectedVersion`, deletion is soft-only, and writes are audited with before/after values. Disabling/deleting the last enabled Critical-covering rule returns a warning and sets the `notificationRules` health component DOWN. `SLA_AT_RISK`, Slack, Teams, and SMS are deferred. In-app storage is implemented.

## Analytics and exports

- `GET /api/v1/analytics/summary` is available to Analysts, Security Leads, and Security Admins. Optional filters are `status`, `severity`, `categoryId`, `department`, `from`, and `to` (ISO-8601 date-times). Results are constrained to the caller's current incident visibility and exclude soft-deleted incidents.
- `GET /api/v1/analytics/incidents.csv` requires the caller's existing `can_export` capability and exports the same filtered, authorized scope. `maxRows` defaults to 50,000 and accepts values from 1 through 50,000; candidates are read in bounded batches. Descriptions are limited to 1,000 characters per row, text fields are CSV-escaped, and formula-like values are guarded against spreadsheet execution.
- `GET /api/v1/analytics/incidents/{id}/report.pdf` requires `can_export` and returns a PDF only after the existing object-level incident authorization succeeds. The single-page report limits its description to 3,500 characters.

The export/report surfaces do not serialize reporter identity fields. Anonymous reporter identity suppression is included in the audit trail.
