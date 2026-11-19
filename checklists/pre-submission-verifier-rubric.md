# Pre-Submission Verifier Rubric (7-Gate Executor → Verifier Checklist)

Never let the agent (or draft pass) that investigated an issue approve its own external submission. Separate the work into two roles:

1. **Executor:** Checks the repository policy, runs the minimal reproduction or oracle check, collects exact versions and verbatim outputs, and drafts the report.
2. **Verifier:** Starts with fresh context, treats every claim in the draft as unproven, re-checks primary sources and live policies, and returns either **PASS** (all 7 gates clear) or **BLOCK** (listing the exact gate that failed).

Every gate below must pass before anything is posted to another project — whether posted directly in an AI-permissive repo or handed to the human contributor in a Draft-Only repo.

---

## Gate 1 — Live Policy & Posting Mode

- [ ] Ran `python3 scripts/check_repo_policy.py <owner/repo>` **live today** (policies change often; cached notes go stale).
- [ ] Checked root, `.github/`, `docs/`, issue/PR templates, `.github/VOUCHED.td`, and `<owner>/.github` org-level policies — including hidden HTML comments (`<!-- ... -->`) and `display: none` blocks.
- [ ] Confirmed the verdict matches the action:
  - `DENY`: **Hard stop.** Do not open issues, comments, or PRs.
  - `DRAFT_ONLY`: Agent prepares a concise evidence note only; the human writes and posts in their own words.
  - `MANUAL_CHECK_REQUIRED`: Read the project's `CONTRIBUTING`, `README`, and recent issue replies manually before proceeding.
  - `ALLOW_WITH_DISCLOSURE`: Eligible to proceed only if Gates 2–7 also pass.
- [ ] Confirmed the task is **not** labeled `good first issue` (reserved for humans learning to code).
- [ ] Confirmed posting stays within a conservative rate cap (for example, at most 2 autonomous posts per repository per week until maintainers engage).

## Gate 2 — Duplicate, Open-PR & Live-Branch Check

- [ ] Searched open issues, recently closed issues, and discussions for duplicates or maintainer decisions already made.
- [ ] Checked open and recently merged pull requests on the default branch to confirm the problem is not already fixed or actively in review.
- [ ] If an overlapping issue or open PR exists, the draft explicitly references it instead of repeating work (and notes merge conflicts or missing `Fixes #...` links only when verified directly).

## Gate 3 — Firsthand Empirical Reproduction & Mechanical Oracle

- [ ] Every claimed output, error message, coordinate, or exit code was actually observed by running the exact commands listed — never inferred from reading docs or guessed from memory.
- [ ] The reproduction uses the smallest self-contained input possible in a clean environment (e.g., an empty temp folder) and includes a nearby **control check** (what works or what stays unchanged).
- [ ] Exact versions (project release or commit SHA, OS, architecture, runtime version, install method) are recorded verbatim.
- [ ] If an independent mechanical oracle was used (test suite, compiler, Lean 4 kernel, real server/client), integrity checks confirm it did not pass vacuously (no skipped checks, no `sorry`, no dropped rows).

## Gate 4 — Scope, Humility & Boundary Check

- [ ] The submission is small and focused on **one** concrete question, bug, or verified table update.
- [ ] No uninvited code PRs, and zero PRs on PR-closed repositories.
- [ ] Never clicks GitHub **"Approve"** on external code PRs (report mechanical checks in a plain comment only).
- [ ] Explicitly states what was **not** tested (e.g., offline bundle vs. fresh online install, CLI vs. web UI, macOS vs. Windows/Linux).
- [ ] Security vulnerabilities are **never** posted publicly — only reported privately through the project's security channel after firsthand confirmation.

## Gate 5 — Links, Revisions & Verbatim Accuracy

- [ ] Every URL, commit SHA, PR/issue number, file path, and line range resolves and matches the exact quoted text or behavior at that revision.
- [ ] Every quoted error message or terminal snippet matches the actual run character for character (with only sensitive local paths scrubbed cleanly).
- [ ] Claims about maintainer replies, merged PRs, or remaining items cite primary links rather than summaries from memory.

## Gate 6 — Privacy, Secret & Clean-Data Scrub

- [ ] All sample inputs use obviously invented data (such as `orders@example.org`, `invoice 42`, `INV-001`).
- [ ] Zero API keys, tokens, cookies, passwords, or private hostnames appear anywhere in pasted logs, commands, or screenshots.
- [ ] Zero local home directory paths, personal email addresses, or private/client project names appear in the draft.

## Gate 7 — Honest AI Disclosure & Attribution Compliance

- [ ] AI involvement is disclosed honestly in the exact format and location the target project requests (`Assisted-by:`, `Generated-by:`, issue/PR note, or template checkbox).
- [ ] Forbidden trailers (`Co-Authored-By` for AI tools, or unauthorized `Signed-off-by` / DCO lines) are stripped wherever disallowed.
- [ ] Authorship matches the posting mode: in `DRAFT_ONLY` repos, the output is a short evidence brief for the human rather than ready-to-paste AI prose.

---

## Verifier Sign-Off Block

Copy this block into your internal review log before publishing or handing off a draft:

```markdown
### Independent Verifier Sign-Off
- **Target:** `<owner/repo>#<issue or new issue>`
- **Policy check (`check_repo_policy.py`):** `<VERDICT>` (checked `<YYYY-MM-DD>`)
- **Gate 1 (Live policy & mode):** PASS / BLOCK — <evidence>
- **Gate 2 (Duplicates & open PRs):** PASS / BLOCK — <evidence>
- **Gate 3 (Empirical repro / oracle):** PASS / BLOCK — <exact command & versions>
- **Gate 4 (Scope & limits):** PASS / BLOCK — <evidence>
- **Gate 5 (Links & line accuracy):** PASS / BLOCK — <commit SHA checked>
- **Gate 6 (Privacy & secret scrub):** PASS / BLOCK — <evidence>
- **Gate 7 (AI disclosure & trailers):** PASS / BLOCK — <exact disclosure line>
- **Final decision:** APPROVED FOR HUMAN POST / APPROVED FOR AUTONOMOUS POST / BLOCKED
```
