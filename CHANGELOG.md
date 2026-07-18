# Changelog

## 0.7.0 - 2026-07-19

- Add repeatable `--ignore-rule RULE-ID` exceptions for reviewed project-specific findings.
- Apply exceptions consistently to text, JSON, Markdown, SARIF, score, summaries, and CI exit codes.
- Record ignored rule IDs and the number of excluded findings in generated reports.

## 0.6.1 - 2026-07-19

- Add repository-relative file and line locations to SARIF findings.
- Preserve correct locations when ordered migrations from multiple files are scanned together.
- Expand CLI regression coverage to 27 tests.

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
