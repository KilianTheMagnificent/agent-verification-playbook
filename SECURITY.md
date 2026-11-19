# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Scope

`agent-verification-playbook` is a read-only local policy scanner and documentation repository. It does not handle logins, passwords, encryption, or backups.

## Reporting a Vulnerability

If you find a security issue — such as a bypass in hidden HTML/CSS anti-agent trap detection, unsafe URL or subprocess handling in `scripts/check_repo_policy.py`, or a denial-of-service parser bug — please report it privately via GitHub's [Private Vulnerability Reporting](https://github.com/KilianTheMagnificent/agent-verification-playbook/security/advisories/new) rather than opening a public issue.

Confirmed reports receive an offline regression test in `tests/test_check_repo_policy.py` alongside the fix.
