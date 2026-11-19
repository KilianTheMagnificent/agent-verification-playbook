# Release Smoke-Audit Template

Use this template when testing a new release, release candidate, or merged fix from a clean installation.
Keep the audit strictly empirical: record every command you ran, what you expected before running it, and what actually happened.

---

## Target release

- **Repository:** `<owner/repo>`
- **Release tag / commit SHA:** `<e.g., v2.16.0 or full/short SHA>`
- **Date tested:** `<YYYY-MM-DD>`
- **Environment:** `<OS, architecture, runtime version>`
- **Install route tested:** `<exact install or build command from a fresh temp directory>`

## Smoke-check matrix

| # | Check | Exact command or action | Expected result | Observed result | Exit code | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Fresh install / version check | `<e.g., tool --version>` | Prints `<expected version>` | `<verbatim output>` | `0` | PASS / FAIL |
| 2 | Core happy path | `<exact command with invented input>` | `<expected output>` | `<verbatim output>` | `0` | PASS / FAIL |
| 3 | Unchanged behavior (survival check) | `<exact command checking nearby edge case>` | `<value stays intact>` | `<verbatim output>` | `0` | PASS / FAIL |
| 4 | Error / boundary case | `<exact command with malformed input>` | Clear error message, non-zero exit | `<verbatim output>` | `1` | PASS / FAIL |

## First failure or friction point (if any)

- **Step:** `#<number>`
- **Command:** `<exact command>`
- **Verbatim output:**

```text
<exact error text or unexpected output; scrub personal paths and tokens>
```

- **Comparison with prior release (if checked):** `<e.g., v2.15.0 returned exit code 0 with ...>`

## Scope & limits

- **Covered:** `<e.g., fresh clone install, CLI smoke checks, offline unit suite>`
- **Not covered:** `<e.g., GUI, Windows/Linux, network-dependent commands>`

## AI assistance disclosure

<!-- Adapt to the target project's policy; in Draft-Only repos, write the report yourself. -->
AI assistance disclosure: `<tool/model name>` helped run the smoke-check script and capture verbatim outputs; all listed commands were executed against `<tag/SHA>` and verified directly.
