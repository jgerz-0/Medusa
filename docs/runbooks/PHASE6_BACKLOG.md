# Phase 6 Task Backlog

The following backlog decomposes the Phase 6 reporting and frontend objectives into fifteen narrowly scoped tasks. Each task is intended to ship as a standalone pull request so we maintain short review cycles and clear audit trails. Reference this backlog while planning sprint work or creating GitHub issues.

> **Security Posture:** Every change must preserve existing RBAC guards, scope enforcement, and audit logging. When in doubt, add controller tests before expanding functionality.

## 1. Add pagination controls to `/scans`
- **Goal:** Accept `limit` and `offset` query parameters on the scans collection endpoint and return pagination metadata (`total`, `limit`, `offset`).
- **Key Touchpoints:** `controller/routes/scans.py`, `tests/controller/scans/test_list_scans.py`, OpenAPI schema.
- **Acceptance Criteria:** Endpoint bounds responses, metadata present in JSON, defaults documented, invalid parameters return 422.
- **Test Focus:** Extend controller tests to cover default pagination and non-zero offsets.

## 2. Cover `/scans` pagination in controller tests
- **Goal:** Expand the controller test suite to seed >50 scans, exercise multiple `limit`/`offset` combinations, and assert response metadata.
- **Key Touchpoints:** `tests/controller/scans/test_list_scans.py` (new parametrized cases), fixtures in `tests/controller/conftest.py`.
- **Acceptance Criteria:** Tests validate ordering, enforce maximum limit guardrails, and confirm audit trail entries when pagination params are used.
- **Test Focus:** `pytest tests/controller/scans/test_list_scans.py`.

## 3. Paginate `/findings` responses server-side
- **Goal:** Apply the `limit`/`offset` pattern to findings aggregation, ensuring the controller handles large datasets efficiently.
- **Key Touchpoints:** `controller/routes/findings.py`, query builders in `controller/services/findings.py`.
- **Acceptance Criteria:** Endpoint returns pagination metadata, respects severity/status filters, and continues to enforce scope restrictions.
- **Test Focus:** Extend findings controller tests to cover pagination + filtering combos.

## 4. Test `/findings` pagination and filters
- **Goal:** Build regression tests that verify the interplay between pagination, severity filters, status filters, and audit metadata.
- **Key Touchpoints:** `tests/controller/findings/test_list_findings.py` (new file), fixtures creating diverse severity/status findings.
- **Acceptance Criteria:** Tests cover boundary offsets, invalid parameter handling, and RBAC guard enforcement.
- **Test Focus:** `pytest tests/controller/findings`.

## 5. Normalize findings timeline statuses
- **Goal:** Update `_build_timeline_buckets` to track `pending_validation`, `open`, and `invalidated` statuses instead of legacy states.
- **Key Touchpoints:** `controller/services/findings.py`, any shared enums or constants.
- **Acceptance Criteria:** Timeline bucket computation matches documented lifecycle, legacy statuses removed.
- **Test Focus:** Unit tests validating bucket counts after refactor.

## 6. Fix findings filter status options in the UI
- **Goal:** Align the frontend status dropdown with the normalized controller statuses.
- **Key Touchpoints:** `frontend/components/findings/Filters.tsx`, related TypeScript types or constants.
- **Acceptance Criteria:** Dropdown renders only supported statuses with secure copy, uses enums shared with the API client.
- **Test Focus:** `npm test -- FindingsFilters`, manual smoke test via Next.js dev server.

## 7. Revise findings timeline UI and types
- **Goal:** Update the timeline component to display counts for the normalized statuses and refresh copy to explain the workflow.
- **Key Touchpoints:** `frontend/components/findings/Timeline.tsx`, types in `frontend/types/findings.ts`.
- **Acceptance Criteria:** UI handles zero-count states, copy mentions validation workflow, TypeScript types align with backend schema.
- **Test Focus:** `npm test -- FindingsTimeline`, storybook snapshot if available.

## 8. Add unit tests for timeline bucket aggregation
- **Goal:** Create targeted tests that feed synthetic findings into `_build_timeline_buckets`.
- **Key Touchpoints:** `tests/services/test_findings_timeline.py` (new), leveraging factories/fixtures.
- **Acceptance Criteria:** Tests cover mixed statuses, ensure counts decrement when findings are invalidated, and document edge cases in comments.
- **Test Focus:** `pytest tests/services/test_findings_timeline.py`.

## 9. Document the `/scans` collection contract
- **Goal:** Produce a docs page describing query parameters, pagination metadata, and RBAC requirements.
- **Key Touchpoints:** New markdown file under `docs/interfaces/` (e.g., `docs/interfaces/SCANS_COLLECTION.md`).
- **Acceptance Criteria:** Includes request/response examples, error handling, and notes on audit logging.
- **Test Focus:** Markdown linting via `pre-commit`.

## 10. Test Jira ticket creation endpoint
- **Goal:** Add controller tests for `/tickets/jira` covering RBAC guards, scope enforcement, and job queueing.
- **Key Touchpoints:** `tests/controller/tickets/test_jira.py`, fixtures mocking external integrations.
- **Acceptance Criteria:** Tests assert audit log entries, payload hashing, and failure handling when queueing fails.
- **Test Focus:** `pytest tests/controller/tickets/test_jira.py`.

## 11. Test GitHub ticket creation endpoint
- **Goal:** Mirror the Jira coverage for `/tickets/github`, validating repository normalization and audit logging.
- **Key Touchpoints:** `tests/controller/tickets/test_github.py`.
- **Acceptance Criteria:** Tests confirm invalid repositories are rejected, payload hashing is deterministic, and audit events fire.
- **Test Focus:** `pytest tests/controller/tickets/test_github.py`.

## 12. Publish ticketing API documentation
- **Goal:** Document Jira and GitHub ticket APIs with request/response schemas and required roles.
- **Key Touchpoints:** New markdown doc under `docs/interfaces/TICKETING_APIS.md` referencing controller routes and RBAC constraints.
- **Acceptance Criteria:** Includes curl examples, scope requirements, and audit considerations.
- **Test Focus:** Markdown lint via `pre-commit`.

## 13. Exercise report export flows in tests
- **Goal:** Mock report storage interactions and validate checksum/metadata generation, including 502 error handling.
- **Key Touchpoints:** `tests/controller/reports/test_exports.py`, storage adapters under `controller/services/reports.py`.
- **Acceptance Criteria:** Tests cover successful export creation, storage failure paths, and ensure audit logs persist.
- **Test Focus:** `pytest tests/controller/reports/test_exports.py`.

## 14. Paginate report export listings
- **Goal:** Extend `/reports/export` to accept pagination parameters and emit metadata.
- **Key Touchpoints:** `controller/routes/reports.py`, service/query logic, OpenAPI schema.
- **Acceptance Criteria:** Endpoint enforces sane max limits, defaults documented, and pagination metadata included in responses.
- **Test Focus:** Controller tests covering pagination + RBAC.

## 15. Teach the frontend to page through report exports
- **Goal:** Update `fetchReportExports` (and consumers) to send pagination parameters and render controls.
- **Key Touchpoints:** `frontend/lib/api/reportExports.ts`, UI components under `frontend/components/reports/`.
- **Acceptance Criteria:** UI displays pagination controls consistent with design system, handles loading/empty states, and uses secure copy.
- **Test Focus:** `npm test -- ReportExports`, manual smoke test.

---
**Execution Guidance:**
- Keep pull requests narrowly scoped to a single task from this list.
- Update documentation alongside code changes.
- Run `pre-commit run --all-files`, targeted `pytest` suites, and `npm test` for touched frontend modules before pushing.
- Coordinate with infrastructure owners before modifying Terraform or Helm manifests to satisfy pagination metadata storage needs.
