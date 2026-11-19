# Stale Issue / Multi-Item Tracker Follow-Up Template

Use this template to post a concise, commit-pinned status check on an older issue or multi-item tracker — crediting merged fixes, separating resolved items from remaining items, and surfacing open PR overlaps cleanly.

---

## Reference check

- **Original issue:** `#<issue-number>`
- **Checked against:** `<branch>` at commit `<short SHA>` (`<full commit URL>`) on `<YYYY-MM-DD>`

Thanks to the contributors behind `#<merged-pr-1>` and `#<merged-pr-2>`, which resolved `<N>` of the `<M>` original items.

## Item-by-item status at `<short SHA>`

| Item | Status at `<short SHA>` | Exact file & lines or merged PR | Verification check |
| --- | --- | --- | --- |
| `<Item 1>` | Fixed | Merged in `#<pr>` | Confirmed updated at `<file#L10-L20>` |
| `<Item 2>` | Fixed | Merged in `#<pr>` | Confirmed updated at `<file#L30-L45>` |
| `<Item 3>` | Still open | `<file#L50-L65>` | Still reproduces `<one-line observed proof>` |
| `<Item 4>` | Still open | `<file#L70-L80>` | Still reproduces `<one-line observed proof>` |

## Overlap & open PR notes

- **Related issue(s):** `<e.g., remaining items also appear in #1234>`
- **Open PR(s):** `<e.g., PR #5678 proposes fixes for items 3 and 4, currently has a merge conflict with #9999, and links #1234 only — not this issue>`

## Suggested next step

`<e.g., Keep this issue open until PR #5678 merges, then re-verify the remaining files on main and close.>`

## AI assistance disclosure

<!-- Adapt to the target project's policy; in Draft-Only repos, write the follow-up yourself. -->
AI assistance disclosure: `<tool/model name>` checked the listed files against commit `<short SHA>` and drafted this status table.
