# Security policy

assay is an offensive-security triage tool intended for **authorized testing only**.

## Reporting a vulnerability in assay

Please report vulnerabilities privately using GitHub's
[private vulnerability reporting](https://github.com/cylockholmes/assay/security/advisories/new)
rather than a public issue. Include the affected version (`assay --version`),
steps to reproduce, and the impact you observed.

Areas of particular interest:

- Scope-enforcement bypasses (a request or tool launched against an out-of-scope host)
- Redaction failures (client identifiers reaching the AI payload)
- Command-injection or shell-metacharacter issues in follow-up commands or `replay.sh`
- Credential leakage into logs, reports, or replay files

## Do not include real target data

Never post real client hostnames, IP addresses, credentials, or scan output in
issues, pull requests, or commits. Use `example.com` and RFC 5737 addresses
(`203.0.113.x`). The repository's pre-commit hook (`.githooks/pre-commit`)
blocks the most common cases.

## Responsible use

Only run assay against systems you have written permission to test.
