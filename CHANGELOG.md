# Changelog

## 0.6.0 - 2026-07-19

- Add SARIF 2.1.0 output for GitHub Code Scanning uploads.
- Map Critical/High findings to SARIF errors, Medium to warnings, and Low to notes.
- Include confidence and suggested remediation metadata in every SARIF result.
- Expand CLI regression coverage to 25 tests.

## 0.5.0 - 2026-07-19

- Add review-ready Markdown reports with remediation blocks and verification checklists.
- Add `--format text|json|markdown` and `--output <path>` CLI options.
- Publish the scoped `@carjms/rls-guard` package for public npm distribution.
- Expand CLI regression coverage to 23 tests.

## 0.4.1 - 2026-07-18

- Detect SUPERUSER and BYPASSRLS database roles.
- Reconstruct final migration state for policies, grants, roles, functions, and views.
