# Documentation Walkthrough Template

Use this template when following a project's guide or reference page from scratch as a reader and finding a missing step, broken example, or confusing fork in the road.

---

## Page inspected

- **Document URL:** `<permalink pinned to a commit SHA>`
- **Section / line range:** `<e.g., "Quickstart", lines 21–38>`
- **Date checked:** `<YYYY-MM-DD>`
- **Reader goal:** `<one plain sentence: e.g., "Start the local test server from a JSON config over stdio without reading source code.">`

## Environment

- **Starting state:** Empty temporary directory (no hidden pre-installed fixtures)
- **OS & architecture:** `<e.g., macOS arm64 / Ubuntu x86_64>`
- **Versions:** `<tool and runtime versions>`

## Walkthrough log

Follow the page literally in order and stop at the first gap or mismatch.

| Step | Instruction on the page | Exact command / action taken | Observed result |
| --- | --- | --- | --- |
| 1 | `<quoted step or link>` | `<exact command>` | `<verbatim result / exit code>` |
| 2 | `<quoted step or link>` | `<exact command>` | `<verbatim result / exit code>` |
| 3 | `<quoted step or link>` | `<exact command>` | `<exact error or point where the reader is stuck>` |

## Exact gap or mismatch

- **What the page says or omits:** `<quote the specific sentence or table row>`
- **Why a reader gets stuck:** `<plain explanation — no guesses about internal implementation>`

## Minimal verified example (tested locally)

If you tested a working command or minimal configuration that closes the gap, show the exact command and observed output:

```sh
<exact working command using invented sample data>
```

```text
<verbatim observed output>
```

## Scope & limits

- **Checked:** `<e.g., CLI route described on the page, offline build>`
- **Not checked:** `<e.g., HTTP transport, web UI, other operating systems>`

## AI assistance disclosure

<!-- Adapt to the target project's policy; in Draft-Only repos, write the report yourself. -->
AI assistance disclosure: `<tool/model name>` ran the walkthrough commands and recorded the verbatim outputs against `<commit SHA>`.
