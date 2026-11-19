---
name: Bug report
about: Report a scanner misclassification, parser bug, or broken template/checklist instruction
title: ""
labels: ""
assignees: ""
---

> **Security notice:** For a suspected security issue (such as a hidden-trap parser bypass, denial-of-service bug, or unsafe subprocess/URL handling in `scripts/check_repo_policy.py`), do **not** open a public issue. Report it privately using [GitHub Private Vulnerability Reporting](https://github.com/KilianTheMagnificent/agent-verification-playbook/security/advisories/new) (see [SECURITY.md](https://github.com/KilianTheMagnificent/agent-verification-playbook/blob/main/SECURITY.md)).
>
> **Privacy notice:** Share short, **invented** or public policy snippets only. Keep private tokens, local home paths, and personal contact details out of public reports.

## Environment

- **Python version** (`python3 --version`):
- **OS / shell**:
- **agent-verification-playbook commit or tag** (`git rev-parse --short HEAD`):

## Command run

```sh
# Paste the exact command you ran (for example, python3 scripts/check_repo_policy.py --local-dir ...)
```

## Sample policy or input

```text
# Short invented or public policy snippet that reproduced the issue
```

## Expected behavior

What verdict (`ALLOW_WITH_DISCLOSURE`, `DENY`, `DRAFT_ONLY`, or `MANUAL_CHECK_REQUIRED`), exit code, or output did you expect?

## Actual behavior

```text
# Paste the exact terminal output and exit code
```
