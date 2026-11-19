# agent-verification-playbook

[![CI](https://github.com/KilianTheMagnificent/agent-verification-playbook/actions/workflows/ci.yml/badge.svg)](https://github.com/KilianTheMagnificent/agent-verification-playbook/actions/workflows/ci.yml)

A zero-dependency toolkit and field guide for non-coders who direct AI agents to make verifiable, policy-respecting open-source contributions.

It combines three practical pieces:

1. **A pre-flight AI-policy scanner (`scripts/check_repo_policy.py`)** — Python 3.9+ standard library only. Checks repository and org-level `.github` policy files, catches hidden HTML comments (`<!-- ... -->`) and `display: none` anti-agent traps, detects `.github/VOUCHED.td` outsider gates, and prints exact file/line evidence.
2. **Empirical-proof issue templates (`templates/`)** — five focused templates for bug reproductions, release smoke audits, documentation walkthroughs, stale-tracker follow-ups, and mechanical-oracle checks.
3. **Verification playbooks (`checklists/`)** — the 7-gate independent Executor → Verifier rubric and a plain-language guide to verifying software behavior without reading code.

## Quickstart

Requires **Python 3.9 or newer** and **Git** (no external Python packages). For live GitHub scans, the scanner uses `gh` CLI when installed and authenticated, or falls back to GitHub HTTPS endpoints automatically.

```sh
git clone https://github.com/KilianTheMagnificent/agent-verification-playbook.git
cd agent-verification-playbook
python3 -m unittest discover -s tests -v
python3 scripts/check_repo_policy.py --local-dir .
```

Running the last command against this repository prints:

```text
Target:  .
Verdict: ALLOW_WITH_DISCLOSURE
Scanned: 1 file(s)
  - CONTRIBUTING.md

Policy findings:
  [ALLOW_WITH_DISCLOSURE] AI_ALLOWED_WITH_DISCLOSURE at CONTRIBUTING.md:5
    Reason:  Policy explicitly welcomes or permits AI-assisted contributions.
    Excerpt: AI-assisted bug reports and policy-pattern suggestions are welcome when verified firsthand and honestly disclosed (for example, noting which AI tool helped c...

Disclosure & workflow hints:
  [HINT] OUTSIDE_PR_CLOSED_HINT at CONTRIBUTING.md:15
    Note:    Outside pull requests are closed; participate via issues only.
    Excerpt: ## Pull requests are turned off
  [HINT] OUTSIDE_PR_CLOSED_HINT at CONTRIBUTING.md:17
    Note:    Outside pull requests are closed; participate via issues only.
    Excerpt: Andre directs development of this repository with AI coding assistants and cannot personally review outside code changes. Outside pull requests are turned of...
```

### Scanning a live GitHub repository

```sh
# Auto mode (uses `gh` CLI when available, otherwise HTTPS raw/REST API)
python3 scripts/check_repo_policy.py owner/repo

# Machine-readable JSON + strict exit codes for scripts or pre-flight hooks
python3 scripts/check_repo_policy.py owner/repo --json --strict

# Offline check of a local checkout plus an optional org-level .github mirror
python3 scripts/check_repo_policy.py --local-dir ./path/to/repo --org-dir ./path/to/org-dot-github
```

## Policy verdicts

Strictest rule wins across all scanned files (`CONTRIBUTING.*`, `AI_POLICY.*`, `AGENTS.md`, `CLAUDE.md`, `.github/VOUCHED.td`, `.github/ISSUE_TEMPLATE/*`, `.github/PULL_REQUEST_TEMPLATE*`, and `<owner>/.github` equivalents):

| Verdict | `--strict` exit code | Meaning |
| --- | :---: | --- |
| `ALLOW_WITH_DISCLOSURE` | `0` | Policy explicitly welcomes or permits AI-assisted work with disclosure, and no ban, hidden trap, vouch gate, or human-prose-only rule matched. |
| `DENY` | `2` | Hard stop: explicit AI ban, hidden `<!-- ... -->` or `display: none` anti-agent trap, or `VOUCHED.td` outsider gate detected. |
| `DRAFT_ONLY` | `3` | Local AI testing or research may be allowed, but prose must be written and posted by a human in their own words (or autonomous agents are banned). |
| `MANUAL_CHECK_REQUIRED` | `4` | No explicit AI policy was found, a fetch warning occurred, or unexplained hidden text needs manual review. Silence is never assumed to be consent. |

Invalid CLI arguments, invalid repo slugs, or missing local directories return exit code `1`.

## What's inside

### Pre-flight scanner & tests

- [`scripts/check_repo_policy.py`](scripts/check_repo_policy.py) — executable CLI and importable Python module (`scan_local_dir`, `scan_github_repo`, `scan_content`, `extract_html_comments`, `extract_display_none_blocks`).
- [`tests/test_check_repo_policy.py`](tests/test_check_repo_policy.py) — offline `unittest` suite covering AI-friendly policies, human-prose Draft-Only policies, AI bans, hidden HTML comment traps (including entity-obfuscated and unclosed comments), hidden `display: none` / CSS-class / `hidden`-attribute traps, `VOUCHED.td` gates, silent repos, org-level `.github` overrides, and strict CLI exit codes.

### Empirical-proof issue templates

- [`templates/bug-repro.md`](templates/bug-repro.md) — minimal reproduction, exact environment, expected vs. actual output, control check, and AI disclosure.
- [`templates/release-smoke-audit.md`](templates/release-smoke-audit.md) — clean-install smoke-check matrix for new releases and release candidates.
- [`templates/docs-walkthrough.md`](templates/docs-walkthrough.md) — fresh-reader step-by-step log pinning the exact line where a guide breaks or omits a step.
- [`templates/stale-tracker-table.md`](templates/stale-tracker-table.md) — commit-pinned status table for multi-item issues and stale tracker follow-ups.
- [`templates/mechanical-proof-check.md`](templates/mechanical-proof-check.md) — self-contained proof or oracle check with anti-shortcut integrity checks and explicit scope limits.

### Playbooks & verification rubrics

- [`checklists/pre-submission-verifier-rubric.md`](checklists/pre-submission-verifier-rubric.md) — the 7-gate independent Executor → Verifier checklist and sign-off block.
- [`checklists/behavioral-verification-without-reading-code.md`](checklists/behavioral-verification-without-reading-code.md) — plain-language guide to the four-invoice check and mechanical oracles, grounded in public examples ([`KilianTheMagnificent/inbox-guard`](https://github.com/KilianTheMagnificent/inbox-guard), [`modelcontextprotocol/inspector#2980`](https://github.com/modelcontextprotocol/inspector/issues/2980) → [`PR #3016`](https://github.com/modelcontextprotocol/inspector/pull/3016), and [`google-deepmind/formal-conjectures#7590`](https://github.com/google-deepmind/formal-conjectures/issues/7590)).

## Scope & limitations

- **Heuristics never replace reading live rules.** `check_repo_policy.py` catches common policy wording, `VOUCHED.td` gates, and hidden HTML/CSS traps, but maintainers revise rules often and may phrase restrictions in unexpected ways or host them on external docs sites. Always read the target project's live contributing guide yourself before posting.
- **Read-only local utility.** This repository does not handle logins, passwords, encryption, or backups.

## Current status and how this was built

**Status:** `0.1` — active, zero-dependency, tested offline on Python 3.9+.

**How this was built:** Andre Romero directs development of this repository using AI coding assistants and verifies results behaviorally rather than by hand-auditing every line of code. The policy scanner is verified against an offline unit test suite covering real-world policy categories and synthetic hidden anti-agent traps, plus fresh-clone runs following this README literally. Because Andre cannot personally review outside code changes, outside pull requests are turned off; bug reports and new policy-pattern suggestions are welcome via issues (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

## License

Dual-licensed: **MIT** for code, scripts, tests, and workflows; **CC BY 4.0** for guides, checklists, and templates. See [`LICENSE`](LICENSE) for full terms.
