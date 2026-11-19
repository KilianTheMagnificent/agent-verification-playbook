# Mechanical Proof / Oracle Verification Template

Use this template when a claim is backed by an independent mechanical oracle — such as a proof assistant (Lean 4), compiler, type checker, schema validator, parser, or reproducible test harness — rather than prose reasoning alone.

---

## Claim & target

- **Target file & revision:** `<permalink with commit SHA and line range>`
- **Plain-language statement of the finding:** `<one or two clear sentences explaining the contradiction or failure without jargon>`

## Mechanical oracle & environment

- **Oracle tool & version:** `<e.g., Lean 4.x.y, DuckDB 1.x.y, Python 3.x.y>`
- **Platform:** `<OS & architecture>`
- **Dependencies / offline status:** `<e.g., stdlib only, or exact lockfile/toolchain version>`

## Self-contained check

Include the smallest self-contained file or script anyone can run from scratch:

```text
<minimal self-contained proof, query, or test script using invented data>
```

## Exact command & verbatim oracle output

```sh
<exact verification command, including any integrity checks such as axiom printing or strict flags>
```

```text
<verbatim output and exit code>
```

## Integrity checks (anti-shortcut verification)

Confirm the oracle did not pass vacuously or via shortcuts:

- [ ] Exit code checked explicitly (`0` for expected pass, non-zero for expected fail)
- [ ] No placeholders, skipped tests, or unproven assumptions (e.g., zero `sorry`, zero custom axioms beyond standard foundations)
- [ ] Tested a nearby control case to confirm the check fails when the bug is absent (or passes when fixed)

## What this oracle establishes — and what it does NOT

- **Establishes:** `<exact narrow statement proven by the run>`
- **Does NOT establish:** `<explicit boundary, e.g., does not judge intended mathematical wording or downstream app behavior>`

## AI assistance disclosure

<!-- Adapt to the target project's policy; in Draft-Only repos, write the report yourself. -->
AI assistance disclosure: `<tool/model name>` constructed the check artifact and ran the oracle; the verbatim output above was produced by `<oracle tool & version>` against commit `<short SHA>`.
