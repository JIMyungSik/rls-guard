# Security Policy

## Scope

RLS Guard is a static first-pass scanner. A clean report is not a security guarantee and does not replace live, role-based access tests or a project-specific audit.

## Reporting a vulnerability

Please do not include service-role keys, database passwords, connection strings, customer data, or private migration files in a public issue.

For a vulnerability in RLS Guard itself, use GitHub's private vulnerability reporting for this repository. Include:

- affected version;
- minimal synthetic SQL that reproduces the problem;
- expected and actual result;
- potential impact.

For false negatives or false positives that can be demonstrated without sensitive data, use the repository's issue forms.

## Response targets

This is a small open-source project, not a monitored commercial security service. We aim to acknowledge a complete report within 7 days and will publish a fix and release notes when the issue is confirmed. Do not rely on these targets for incident response.

## Supported versions

Only the latest npm release and current web version receive fixes.
