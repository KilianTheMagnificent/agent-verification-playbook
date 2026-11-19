# Worked Case Study: End-to-End Verification Across MCP, `wcp`, and `luck-filter`

This case study walks through three real-world verification workflows executed without hand-auditing source code:

1. **Pre-flight policy scanning** with [`scripts/check_repo_policy.py`](../scripts/check_repo_policy.py) on two Model Context Protocol repositories with very different contribution rules (`modelcontextprotocol/python-sdk` vs. `modelcontextprotocol/servers`).
2. **Empirical stdio and CLI verification** on [`modelcontextprotocol/inspector#2980`](https://github.com/modelcontextprotocol/inspector/issues/2980) (merged in [`PR #3016`](https://github.com/modelcontextprotocol/inspector/pull/3016)) and [`modelcontextprotocol/inspector#3021`](https://github.com/modelcontextprotocol/inspector/issues/3021).
3. **Using GitHub Actions CI as an independent mechanical oracle** to catch real Linux, concurrency, and boundary-math bugs in [`KilianTheMagnificent/wcp`](https://github.com/KilianTheMagnificent/wcp) and [`KilianTheMagnificent/luck-filter`](https://github.com/KilianTheMagnificent/luck-filter) after local macOS runs passed.

Every command output and commit SHA below comes from firsthand runs rather than synthetic mockups.

---

## Part 1: Pre-Flight Policy Scanning (`python-sdk` vs. `servers`)

Before touching any external repository, run Gate 1 of the [Pre-Submission Verifier Rubric](../checklists/pre-submission-verifier-rubric.md) using the policy scanner in strict mode:

```sh
python3 scripts/check_repo_policy.py modelcontextprotocol/python-sdk --strict
python3 scripts/check_repo_policy.py modelcontextprotocol/servers --strict
```

### 1A. `modelcontextprotocol/python-sdk` — catches `DRAFT_ONLY` (`HUMAN_PROSE_REQUIRED`)

Observed output (exit code `3` with `--strict`):

```text
Target:  modelcontextprotocol/python-sdk
Verdict: DRAFT_ONLY
Scanned: 13 file(s)
  - .github/ISSUE_TEMPLATE/bug.yaml
  - .github/ISSUE_TEMPLATE/config.yaml
  - .github/ISSUE_TEMPLATE/feature-request.yaml
  - .github/ISSUE_TEMPLATE/question.yaml
  - .github/ISSUE_TEMPLATE/v2-feedback.yaml
  - .github/pull_request_template.md
  - AGENTS.md
  - CLAUDE.md
  - CONTRIBUTING.md
  - modelcontextprotocol/.github/.github/ISSUE_TEMPLATE/bug_report.md
  - modelcontextprotocol/.github/.github/ISSUE_TEMPLATE/feature_request.md
  - modelcontextprotocol/.github/.github/pull_request_template.md
  - modelcontextprotocol/.github/CONTRIBUTING.md

Policy findings:
  [DRAFT_ONLY] HUMAN_PROSE_REQUIRED at CONTRIBUTING.md:38
    Reason:  Policy requires human-written prose in the contributor's own words.
    Excerpt: - **Own it.** You can explain the change and the reasoning in your own words, and when a maintainer asks a question the answer comes from you rather than bei...
```

**What this prevented:** Even though `AGENTS.md` and `CLAUDE.md` exist in the repository for local development, `CONTRIBUTING.md:38` requires human ownership and prose in the contributor's own words. Strict exit code `3` (`DRAFT_ONLY`) blocks autonomous posting and limits any AI agent to local investigation and concise evidence notes for a human to rewrite.

### 1B. `modelcontextprotocol/servers` — `MANUAL_CHECK_REQUIRED` uncovers an issues-only rule

Observed output (exit code `4` with `--strict`):

```text
Target:  modelcontextprotocol/servers
Verdict: MANUAL_CHECK_REQUIRED
Scanned: 10 file(s)
  - .github/ISSUE_TEMPLATE/1-bug_report.yml
  - .github/ISSUE_TEMPLATE/2-feature_request.yml
  - .github/ISSUE_TEMPLATE/config.yml
  - .github/pull_request_template.md
  - AGENTS.md
  - CONTRIBUTING.md
  - modelcontextprotocol/.github/.github/ISSUE_TEMPLATE/bug_report.md
  - modelcontextprotocol/.github/.github/ISSUE_TEMPLATE/feature_request.md
  - modelcontextprotocol/.github/.github/pull_request_template.md
  - modelcontextprotocol/.github/CONTRIBUTING.md

Disclosure & workflow hints:
  [HINT] DCO_OR_CLA_HINT at AGENTS.md:26
    Note:    Repository mentions a CLA or DCO requirement.
    Excerpt: | [`pr-flow`](.claude/skills/pr-flow/SKILL.md) | Issue to PR: branch, DCO signoff and repair, the gate, client evidence, `addCloseIssueReferences`, the Copil...

Warnings:
  - No explicit AI contribution policy was matched; read the repository guidelines manually before acting.
```

**Why "silence is never consent" mattered:** Because no explicit AI-allow wording matched, `check_repo_policy.py` refused to return `ALLOW_WITH_DISCLOSURE` and instead exited `4` (`MANUAL_CHECK_REQUIRED`). Reading `modelcontextprotocol/servers/CONTRIBUTING.md` manually immediately surfaced its **issues-only** policy:

> **We accept issues, not pull requests.** Design and implementation are done by the repository maintainers. If you've already built a fix or feature locally, share **the prompt you used** to produce it, not the source code.

Together, these two scans illustrate both halves of Gate 1: automated detection catches explicit `DRAFT_ONLY` / `DENY` clauses with exact line citations, and `MANUAL_CHECK_REQUIRED` forces a live read whenever a repository uses a custom workflow like issues-only prompt-driven development.

---

## Part 2: Empirical stdio and CLI Verification (`modelcontextprotocol/inspector`)

Both Inspector contributions relied strictly on running the real binary with invented inputs and comparing a working control case against the changed or failing case — without needing to audit TypeScript source code.

### 2A. Composable stdio server docs (`inspector#2980` → merged `PR #3016`)

- **Question:** How can a reader confirm that editing a composable test-server JSON config file actually changes the tools advertised over stdio?
- **Empirical check (two runs, one control):**
  1. Start the built composable server over stdio with the shipped `test-servers/configs/demo.json`, list tools through a real MCP client, and invoke `echo` with invented input `{"message": "invoice 42"}`.
     - **Observed:** tools `echo, get_temp` | response `Echo: invoice 42`.
  2. Copy the config, restrict `tools` to `["echo"]` only, restart the server against that copy, and run the same MCP client calls.
     - **Observed:** tool `echo` only | response `Echo: invoice 42`.
- **Outcome:** Posting the tested JSON snippet, verbatim tool lists, echo response, and honest AI disclosure on [`modelcontextprotocol/inspector#2980`](https://github.com/modelcontextprotocol/inspector/issues/2980) led directly to merged [`PR #3016`](https://github.com/modelcontextprotocol/inspector/pull/3016) (*"docs: add a config reference for the composable test server"*).

### 2B. Flag/environment conflict bug (`inspector#3021`: `MCP_CATALOG_PATH` + `--config`)

When testing `@modelcontextprotocol/inspector@2.16.0` (Node `v26.13.1`, macOS arm64), setting `MCP_CATALOG_PATH` to customize the default catalog location broke `--config <file>` across every client entrypoint. Following [`templates/bug-repro.md`](../templates/bug-repro.md), the reproduction isolates the trigger in an empty temp folder with two tiny invented JSON files:

```sh
TESTDIR=$(mktemp -d)
echo '{"mcpServers":{}}' > "$TESTDIR/my-catalog.json"
echo '{"mcpServers":{"demo":{"command":"node","args":["-e",""]}}}' > "$TESTDIR/foreign.json"
```

1. **Control check (`MCP_CATALOG_PATH` unset):**
   ```sh
   env -u MCP_CATALOG_PATH npx -y @modelcontextprotocol/inspector@2.16.0 \
     --cli --config "$TESTDIR/foreign.json" --method servers/list
   ```
   Observed (exit code `0`):
   ```json
   {"servers":[{"name":"demo","type":"stdio","detail":"node -e "}]}
   ```

2. **Failing cases (`MCP_CATALOG_PATH` set, `--config` passed without `--catalog`):**
   ```sh
   MCP_CATALOG_PATH="$TESTDIR/my-catalog.json" npx -y @modelcontextprotocol/inspector@2.16.0 \
     --cli --config "$TESTDIR/foreign.json" --method servers/list
   MCP_CATALOG_PATH="$TESTDIR/my-catalog.json" npx -y --package=@modelcontextprotocol/inspector@2.16.0 \
     mcpdo --config "$TESTDIR/foreign.json" servers/list
   MCP_AUTO_OPEN_ENABLED=false MCP_CATALOG_PATH="$TESTDIR/my-catalog.json" npx -y @modelcontextprotocol/inspector@2.16.0 \
     --web --config "$TESTDIR/foreign.json"
   MCP_CATALOG_PATH="$TESTDIR/my-catalog.json" npx -y @modelcontextprotocol/inspector@2.16.0 \
     --tui --config "$TESTDIR/foreign.json" </dev/null
   ```
   Observed across all four clients (exit code `1`):
   ```text
   --catalog and --config are mutually exclusive. --catalog is the writable catalog; --config is a read-only session file.
   ```

**Why this works without reading code:** One control command (`env -u MCP_CATALOG_PATH` → exit `0`, valid server list) paired with four one-line failing commands (`MCP_CATALOG_PATH=...` → exit `1`, identical rejection message) proves that the ambient environment variable is being treated as an explicit `--catalog` flag before any MCP server connection even begins. Filed as [`modelcontextprotocol/inspector#3021`](https://github.com/modelcontextprotocol/inspector/issues/3021) with exact versions, verbatim outputs, and AI disclosure.

---

## Part 3: CI as an Independent Mechanical Oracle (`wcp` and `luck-filter`)

Passing tests on one developer laptop proves only that the code works on that OS, kernel, scheduler, and Python build. Pushing to fresh GitHub Actions Ubuntu runners across Python `3.11`, `3.12`, and `3.13` acted as an impartial mechanical oracle that immediately caught bugs local macOS runs missed.

### 3A. [`KilianTheMagnificent/wcp`](https://github.com/KilianTheMagnificent/wcp) — Linux syscall, concurrency, and process-reaping bugs

Local macOS tests were green before the initial push. Running the exact same test suite on Linux CI surfaced four concrete defects in succession:

| Commit | Bug caught by CI oracle | Why local macOS missed it | Behavioral fix verified by CI |
| --- | --- | --- | --- |
| `4a289b2` | `RuntimeError: wcp needs os.chmod(dir_fd=, follow_symlinks=False)` on Ubuntu Linux | macOS supports `os.chmod(..., dir_fd=fd, follow_symlinks=False)`; Linux's `fchmodat` rejects `AT_SYMLINK_NOFOLLOW` | Opened file with `os.O_RDONLY \| os.O_NOFOLLOW` via `dir_fd`, verified `stat.S_ISREG` with `os.fstat`, and applied permissions via `os.fchmod` |
| `a3e20b8` | Run prematurely transitioned to `paused` while a sibling task was still in flight | Different scheduling timing on Linux CI exposed the race between one task pausing and a sibling still being `building`, `submit_pending`, or `verifying` | Kept run status `running` until no sibling task remains in flight and live workers drop to zero |
| `b231597` | Intermittent timeout test failure in `tests/test_gitx.py` | Grandchild process reaping took slightly longer under Linux CI load than on a quiet local machine | Waited briefly for grandchild reaping before asserting process exit in the timeout test |
| `ca5d376` | Resource warnings from unclosed SQLite connections in CLI commands and DB tests | Quietly garbage-collected under some local runs, surfaced cleanly under stricter multi-version test runs | Explicitly closed SQLite connections opened by `wcp/cli.py` and `tests/test_db.py` |

### 3B. [`KilianTheMagnificent/luck-filter`](https://github.com/KilianTheMagnificent/luck-filter) — exact boundary probability & CI runner drift

- **Exact boundary check (`3180f16`):** Testing the edge cases of `binomial_test(successes, n, p0)` — which computes $P(X \ge \text{successes})$ under success rate $p_0$ — caught that when `p0 == 1.0` and `0 < successes < n`, the old code returned `0.0` instead of `1.0` (under $p_0 = 1.0$, every trial succeeds, so $X = n$ and $P(X \ge \text{successes}) = 1.0$ for all $\text{successes} \le n$, and `0.0` only when $\text{successes} > n$). You do not need to read logarithms to spot that a 100% coin lands heads at least 3 times in 10 flips with probability `1.0`, not `0.0`.
- **Clean-runner matrix drift (`4ba26d1`):** Ubuntu 26.04 GitHub Actions runners no longer ship preinstalled Python `3.9`/`3.10` toolcaches, immediately catching outdated CI matrix definitions on a clean runner.

---

## Summary: What Each Check Proved — and Its Boundary

| Workflow | Mechanical oracle used | What it proved | What it did **not** prove |
| --- | --- | --- | --- |
| `check_repo_policy.py --strict` | Policy file & hidden-trap scanner | `python-sdk` requires human prose (`DRAFT_ONLY`, exit `3`); `servers` has no matched AI-allow text (`MANUAL_CHECK_REQUIRED`, exit `4`) | That an external docs site or future commit won't change policy wording |
| `inspector#2980` & `#3021` | Live MCP stdio client + `@modelcontextprotocol/inspector@2.16.0` CLI/TUI/Web/mcpdo | Config changes alter advertised stdio tools; exporting `MCP_CATALOG_PATH` breaks `--config` across all four clients while unset `MCP_CATALOG_PATH` succeeds | Behavior on Windows or inside an interactive browser click path after Web starts |
| GitHub Actions CI on `wcp` & `luck-filter` | Fresh Ubuntu Linux containers across Python 3.11–3.13 | Linux `fchmod` compatibility, sibling-task lifecycle race fix, grandchild reaping, SQLite cleanup, and exact `binomial_test` boundaries | Behavior on Windows or non-POSIX filesystems not included in the CI matrix |
