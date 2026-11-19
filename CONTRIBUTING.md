# Contributing to agent-verification-playbook

Issues, bug reports, false-positive/false-negative reports, and new policy-pattern suggestions are welcome via GitHub Issues.

AI-assisted bug reports and policy-pattern suggestions are welcome when verified firsthand and honestly disclosed (for example, noting which AI tool helped collect or test the example).

## What to include in an issue

- Your Python version (`python3 --version`) and operating system.
- The exact command you ran (for example, `python3 scripts/check_repo_policy.py --local-dir ...`).
- A short invented or public policy snippet showing the wording or hidden-HTML trap that misclassified.
- The expected classification (`DENY`, `DRAFT_ONLY`, `ALLOW_WITH_DISCLOSURE`, or `MANUAL_CHECK_REQUIRED`) and the actual output.
- Use invented data and public examples only; keep private tokens, local home paths, and personal contact details out of public reports.

## Pull requests are turned off

Andre directs development of this repository with AI coding assistants and cannot personally review outside code changes. Outside pull requests are turned off; please open an issue instead so confirmed fixes and new policy patterns can be added with offline tests.

## Security issues

For a suspected security vulnerability (such as a parser bug, hidden-trap bypass, or unsafe subprocess/URL handling), please use the private reporting instructions in [SECURITY.md](SECURITY.md) rather than opening a public issue.
