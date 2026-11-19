# Empirical Bug Report Template

Use this template for a focused, single-problem bug report verified firsthand.
Before posting: run `python3 scripts/check_repo_policy.py <owner/repo>`, check the project's live AI policy, search open and closed issues/PRs for duplicates, and replace any personal paths, tokens, or real user data with invented examples (such as `orders@example.org` or `invoice 42`).

---

## Summary

<!-- Replace with one plain sentence naming the exact behavior that fails. -->
`<command or feature>` produces `<unexpected result>` instead of `<expected result>` when `<minimal trigger condition>`.

## Pre-submission checks

- [ ] Searched open and closed issues and open PRs for duplicates
- [ ] Confirmed this is not labeled `good first issue`
- [ ] Reproduced firsthand in a clean environment using invented sample data
- [ ] Scrubbed local paths, credentials, and personal information from all pasted output

## Environment

- **Project version / commit:** `<e.g., v2.15.0 or commit SHA>`
- **Install method:** `<e.g., fresh clone, npm, pip, Homebrew, release tarball>`
- **Operating system & architecture:** `<e.g., macOS 15.x arm64 / Ubuntu 24.04 x86_64>`
- **Runtime / tool versions:** `<e.g., Python 3.12.7, Node.js 22.11.0>`

## Minimal reproduction

Run from an empty temporary directory using invented input:

```sh
# 1. Create the minimal input file
cat <<'EOF' > sample.txt
<minimal invented input>
EOF

# 2. Run the exact failing command
<exact command>
```

## Expected vs. actual behavior

- **Expected:** `<exact expected output, file state, or exit code>`
- **Actual:** `<exact observed output, file state, or exit code>`

### Verbatim output

```text
<paste exact terminal output and exit code; scrub local home directories>
```

## Control check

To isolate the trigger, compare with the closest working case:

```sh
<command with one small change that succeeds>
```

Observed control result: `<exact output and exit code>`.

## Scope & what was not tested

- Tested: `<e.g., CLI offline mode with UTF-8 comma-delimited input>`
- Not tested: `<e.g., web UI, Windows, or other runtimes>`

## AI assistance disclosure

<!-- Adapt this line to the exact format requested by the target repository.
     In Draft-Only repositories, write the entire report yourself in your own words. -->
AI assistance disclosure: `<tool/model name>` assisted with isolating the minimal reproduction and collecting environment output; I ran the commands and verified the observed output firsthand.
