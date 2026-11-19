# Behavioral Verification Without Reading Code

You do not need to read source code to verify whether software does what it promises — **if** you stick to behavioral checks, mechanical oracles, and honest boundaries.

That comes with one hard rule up front: **do not send AI-written code pull requests to other people's projects if you cannot read and defend the code yourself.** Almost every active open-source AI policy requires the human submitting code to understand every line and answer technical review questions directly. Where a non-coder directing AI agents genuinely helps maintainers is **verified context**: reproducible bug reports, fresh-reader documentation walkthroughs, release smoke tests, stale-issue audits, and running your own small tools cleanly.

This guide covers the two core verification patterns that work reliably without reading code, illustrated with real public examples.

---

## 1. Write the acceptance check before the agent runs (The Four-Invoice Check)

If you ask an AI assistant, *"Does this work?"*, you will almost always get a confident *"Yes."* A confident summary is not verification. Instead, before running a tool or checking a fix, write down two short lists on invented data:

1. **What must change** (the exact bug or transformation you asked for).
2. **What must survive untouched** (nearby edge cases that a sloppy fix could silently corrupt or delete).

### Public example: [`KilianTheMagnificent/inbox-guard`](https://github.com/KilianTheMagnificent/inbox-guard)

In `inbox-guard`'s hands-on guide ([`docs/checking-a-change.md`](https://github.com/KilianTheMagnificent/inbox-guard/blob/main/docs/checking-a-change.md)), a non-coder verifies a CSV formula-injection sanitizer using four invented invoices:

- **What should change:** The memos on rows 3 (`INV-002`, starting with `=2+3`) and 5 (`INV-004`, starting with `+2+3`) should each receive a leading apostrophe (`'=2+3` and `'+2+3`).
- **What must survive:**
  - The accounting refund of `-42.50` must keep its minus sign (not get flagged as a dangerous formula).
  - A vendor name containing a comma and a multi-line delivery note inside one cell must stay intact.
  - All five rows (header + four invoices) and four columns must still exist after sanitizing — catching a buggy tool that achieves "zero findings" by silently dropping rows.
  - The original input file must remain unchanged, and re-running the copy command against an existing output filename must refuse to overwrite it (`Output already exists`).
- **Exact exit codes:** Screening the raw file returns exit code `2` (findings detected), screening the reviewed copy returns exit code `0` (clean), and malformed input returns exit code `1` (error).

None of those checks require reading JavaScript. Every step compares plain inputs and plain outputs you can inspect with your own eyes.

---

## 2. Rely on a Mechanical Oracle whenever one exists

A **mechanical oracle** is an independent program with strict pass/fail rules — a real client/server protocol, a database engine, a compiler, a proof assistant, or a fresh-clone test suite. Unlike prose review, a mechanical oracle cannot be persuaded by fluent writing.

### Public example A (Protocol oracle): [`modelcontextprotocol/inspector#2980`](https://github.com/modelcontextprotocol/inspector/issues/2980) → merged [`PR #3016`](https://github.com/modelcontextprotocol/inspector/pull/3016)

- **Problem:** Readers looking at the composable test-server documentation could not easily tell how to start a stdio server from a JSON config file or verify that editing the config actually changed which tools the server exposed.
- **Behavioral check (no TypeScript reading required):**
  1. Start the real built composable server over stdio using the shipped `test-servers/configs/demo.json`.
  2. Ask an actual MCP client to list tools and call `echo` with `{"message": "invoice 42"}`.
     - Observed: tools `echo, get_temp` | response `Echo: invoice 42`.
  3. Make a copy of the JSON file with only `echo` in `tools`, start the server against that copy, and repeat.
     - Observed: tool `echo` only | response `Echo: invoice 42`.
- **Outcome:** Posting the tested configuration example, observed tool lists, echo response, and honest Codex disclosure on `#2980` led directly to merged [`PR #3016`](https://github.com/modelcontextprotocol/inspector/pull/3016), which added the example and its tool-list verification step to the official docs and credited the issue comment.

### Public example B (Formal-verification oracle): [`google-deepmind/formal-conjectures#7590`](https://github.com/google-deepmind/formal-conjectures/issues/7590)

- **Problem:** Eight formalized mathematical statements defined an answer as a single fixed value while quantifying over an input parameter (such as `N` or `k`) that changed the true answer.
- **Mechanical oracle + plain-language sanity check:**
  - **Oracle:** Lean 4's independent proof kernel checked a negation proof for each statement (confirming zero `sorry` placeholders and no unexpected axioms).
  - **Plain-language sanity check:** For `erdos_321`, the formal statement claimed a single natural number equaled `R N` for every `N`, while the concrete cases gave `0` at `N = 0` and at least `1` at `N = 1`. One constant number cannot equal both `0` and `>= 1`.
- **Outcome:** Independent contributors later merged fixes for four of the eight statements (`#7946` and `#8015`), and a concise commit-pinned follow-up table tracked the four remaining declarations cleanly at a verified commit SHA.

---

## 3. Separate what a check proves from what still needs checking

Every behavioral check has a boundary. Naming that boundary explicitly prevents overclaiming and builds trust with maintainers:

| What you tested | What it proves | What it does **NOT** prove |
| --- | --- | --- |
| CLI CSV sanitizer on four invented invoices | Exact CSV bytes, row/column counts, exit codes, and no-overwrite safeguard | How a specific spreadsheet app (Excel, Numbers, Sheets) imports apostrophe-prefixed cells under different locale settings |
| Locally built server with an offline dependency set | Protocol output of the tested binary with two JSON configs | That a fresh online `npm install` or the web UI behaves identically |
| Lean 4 kernel negation proof on a formalized theorem | The Lean declaration as written is logically refutable | Which corrected mathematical statement the maintainers prefer to adopt |
| Offline unit tests on `scripts/check_repo_policy.py` | Known patterns and synthetic hidden traps classify as expected | That a live repository has not updated its policy or phrased a ban in a new way |

---

## 4. Reusable Behavioral Verification Worksheet

Copy this table before running an agent on any change or external bug report. Fill in rows 1–4 **before** executing anything.

| Field | What to record |
| --- | --- |
| **Target & version** | Exact repo, release tag or commit SHA, OS, and runtime version |
| **Invented input & action** | Smallest made-up sample data (`orders@example.org`, `invoice 42`) and exact commands |
| **What must change** | Exact expected output, file diff, or exit code |
| **What must survive** | Nearby valid data, formatting, or original files that must stay intact |
| **Control / failure check** | One working comparison case or error condition that proves the check isn't passing blindly |
| **Observed result** | Verbatim output and exit codes from running the commands |
| **What still needs checking** | Environments, UI paths, or downstream apps outside this run |
| **Who ran it** | Name the tool/agent and note whether a human re-ran or visually confirmed the output |
