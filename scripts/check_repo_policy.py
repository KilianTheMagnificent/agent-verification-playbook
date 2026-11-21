#!/usr/bin/env python3
"""Pre-flight repository AI-policy scanner (Python 3.9+ stdlib only).

Fetches or reads repository policy files (CONTRIBUTING.*, AI_POLICY.*,
AGENTS.md, CLAUDE.md, .github/VOUCHED.td, .github/ISSUE_TEMPLATE/*,
.github/PULL_REQUEST_TEMPLATE*, and org-level .github equivalents), inspects
both visible text and hidden HTML comments / display:none blocks for
anti-agent traps, and classifies the repository into:

  - DENY
  - DRAFT_ONLY
  - ALLOW_WITH_DISCLOSURE
  - MANUAL_CHECK_REQUIRED

Always re-read a project's live policies yourself before contributing.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Set, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

__all__ = [
    "VERDICT_DENY",
    "VERDICT_DRAFT_ONLY",
    "VERDICT_ALLOW_WITH_DISCLOSURE",
    "VERDICT_MANUAL_CHECK_REQUIRED",
    "Finding",
    "ScannedFile",
    "PolicyReport",
    "extract_html_comments",
    "extract_display_none_blocks",
    "scan_content",
    "scan_documents",
    "scan_local_dir",
    "scan_github_repo",
    "format_report_text",
    "main",
]

VERDICT_DENY = "DENY"
VERDICT_DRAFT_ONLY = "DRAFT_ONLY"
VERDICT_ALLOW_WITH_DISCLOSURE = "ALLOW_WITH_DISCLOSURE"
VERDICT_MANUAL_CHECK_REQUIRED = "MANUAL_CHECK_REQUIRED"

USER_AGENT = "agent-verification-playbook-policy-scanner/0.1"
REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

# Candidate file names checked in repo root, .github/, docs/, and org .github.
POLICY_BASENAME_EXACT = {
    "ai_policy.md",
    "ai_policy.txt",
    "ai-policy.md",
    "ai-policy.txt",
    "ai_guidelines.md",
    "ai-guidelines.md",
    "agents.md",
    "claude.md",
    "gemini.md",
    "copilot-instructions.md",
    "vouched.td",
    "issue_template.md",
    "pull_request_template.md",
}
POLICY_STEM_PREFIXES = ("contributing", "ai_policy", "ai-policy", "ai_guidelines", "ai-guidelines")
TEMPLATE_EXTENSIONS = {".md", ".markdown", ".yml", ".yaml", ".txt", ".rst", ".adoc", ".html", ""}
MAX_FILE_BYTES = 512 * 1024  # 512 KiB safety ceiling per fetched policy file

# Direct raw-URL fallback probes when directory listing is unavailable.
RAW_FALLBACK_PATHS = (
    "CONTRIBUTING.md",
    "CONTRIBUTING.rst",
    "CONTRIBUTING.txt",
    "CONTRIBUTING",
    "AI_POLICY.md",
    "AI-POLICY.md",
    "AGENTS.md",
    "CLAUDE.md",
    ".github/CONTRIBUTING.md",
    ".github/CONTRIBUTING.rst",
    ".github/AI_POLICY.md",
    ".github/AI-POLICY.md",
    ".github/AGENTS.md",
    ".github/CLAUDE.md",
    ".github/copilot-instructions.md",
    ".github/VOUCHED.td",
    "VOUCHED.td",
    ".github/ISSUE_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yaml",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/pull_request_template.md",
    "docs/CONTRIBUTING.md",
    "docs/AI_POLICY.md",
    "doc/contributing/ai-guidelines.md",
)


@dataclass(frozen=True)
class Finding:
    """Single matched policy signal or hint with exact file/line evidence."""

    classification: str  # DENY, DRAFT_ONLY, MANUAL_CHECK_REQUIRED, ALLOW_WITH_DISCLOSURE, or HINT
    rule_id: str
    file_path: str
    line: int
    excerpt: str
    reason: str


@dataclass(frozen=True)
class ScannedFile:
    """Policy or template document loaded for inspection."""

    path: str
    content: str
    source: str = "local"


@dataclass
class PolicyReport:
    """Aggregated policy classification report for a repository."""

    target: str
    verdict: str
    scanned_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hints: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "scanned_files": list(self.scanned_files),
            "findings": [asdict(f) for f in self.findings],
            "hints": [asdict(h) for h in self.hints],
            "warnings": list(self.warnings),
        }


def _clean_excerpt(text: str, limit: int = 160) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3].rstrip() + "..."


def _decode_css_escapes(value: str) -> str:
    """Decode simple CSS hex or character escapes (e.g. \\64 -> d, \\- -> -)."""

    def _replace(match: re.Match) -> str:
        hex_part = match.group(1)
        if hex_part:
            try:
                codepoint = int(hex_part, 16)
                if 0 < codepoint <= 0x10FFFF:
                    return chr(codepoint)
            except ValueError:
                return ""
            return ""
        return match.group(2) or ""

    return re.sub(r"\\(?:([0-9a-fA-F]{1,6})\s?|([^\n\r\f0-9a-fA-F]))", _replace, value)


def _strip_css_comments(css: str) -> str:
    """Linear-time removal of CSS /* ... */ comments."""
    out: List[str] = []
    pos = 0
    length = len(css)
    while pos < length:
        start = css.find("/*", pos)
        if start == -1:
            out.append(css[pos:])
            break
        out.append(css[pos:start])
        end = css.find("*/", start + 2)
        if end == -1:
            break
        pos = end + 2
    return "".join(out)


def _css_hiding_reason(declarations: str) -> Optional[str]:
    """Return a hiding mechanism label if CSS declarations hide content."""
    cleaned = _decode_css_escapes(_strip_css_comments(declarations)).lower()
    for part in cleaned.split(";"):
        if ":" not in part:
            continue
        prop, raw_val = part.split(":", 1)
        prop = prop.strip()
        val = re.sub(r"!important\b", "", raw_val).strip()
        if prop == "display" and val == "none":
            return "display: none"
        if prop == "visibility" and val in {"hidden", "collapse"}:
            return f"visibility: {val}"
        if prop == "content-visibility" and val == "hidden":
            return "content-visibility: hidden"
        if prop == "color" and val == "transparent":
            return "color: transparent"
        if prop == "opacity":
            try:
                if float(val) <= 0.02:
                    return f"opacity: {val}"
            except ValueError:
                pass
        if prop == "font-size":
            m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*(?:px|pt|em|rem|%)?$", val)
            if m and float(m.group(1)) == 0.0:
                return f"font-size: {val}"
    return None


def _extract_hidden_css_selectors(text: str) -> Tuple[Set[str], Set[str]]:
    """Find class names and IDs hidden inside <style> blocks."""
    hidden_classes: Set[str] = set()
    hidden_ids: Set[str] = set()
    lower = text.lower()
    pos = 0
    while True:
        start = lower.find("<style", pos)
        if start == -1:
            break
        gt = lower.find(">", start)
        if gt == -1:
            break
        end = lower.find("</style>", gt + 1)
        if end == -1:
            end = len(text)
        css_body = _strip_css_comments(text[gt + 1 : end])
        for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css_body):
            selectors_raw, decls = match.group(1), match.group(2)
            if _css_hiding_reason(decls):
                for sel in selectors_raw.split(","):
                    sel = sel.strip()
                    for cls in re.findall(r"\.([A-Za-z0-9_-]+)", sel):
                        hidden_classes.add(cls.lower())
                    for elem_id in re.findall(r"#([A-Za-z0-9_-]+)", sel):
                        hidden_ids.add(elem_id.lower())
        pos = end + 8
    return hidden_classes, hidden_ids


def _parse_html_attributes(attr_text: str) -> Dict[str, str]:
    """Linear-time parser for HTML tag attributes."""
    attrs: Dict[str, str] = {}
    i = 0
    n = len(attr_text)
    while i < n:
        while i < n and attr_text[i].isspace():
            i += 1
        if i >= n or attr_text[i] == "/":
            break
        name_start = i
        while i < n and not attr_text[i].isspace() and attr_text[i] not in "=/<>":
            i += 1
        name = attr_text[name_start:i].lower()
        if not name:
            i += 1
            continue
        while i < n and attr_text[i].isspace():
            i += 1
        value = ""
        if i < n and attr_text[i] == "=":
            i += 1
            while i < n and attr_text[i].isspace():
                i += 1
            if i < n and attr_text[i] in ('"', "'"):
                quote = attr_text[i]
                i += 1
                val_start = i
                while i < n and attr_text[i] != quote:
                    i += 1
                value = attr_text[val_start:i]
                if i < n:
                    i += 1
            else:
                val_start = i
                while i < n and not attr_text[i].isspace():
                    i += 1
                value = attr_text[val_start:i]
        attrs[name] = html.unescape(value)
    return attrs


def _find_tag_end(text: str, start: int) -> int:
    """Find the closing '>' of an HTML tag starting at '<', respecting quotes."""
    i = start + 1
    n = len(text)
    quote: Optional[str] = None
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
        else:
            if ch in ('"', "'"):
                quote = ch
            elif ch == ">":
                return i
        i += 1
    return -1


def _strip_html_tags(fragment: str) -> str:
    """Strip HTML tags linearly without catastrophic regexes."""
    out: List[str] = []
    i = 0
    n = len(fragment)
    while i < n:
        lt = fragment.find("<", i)
        if lt == -1:
            out.append(fragment[i:])
            break
        out.append(fragment[i:lt])
        gt = _find_tag_end(fragment, lt)
        if gt == -1:
            break
        out.append(" ")
        i = gt + 1
    return html.unescape("".join(out))


def extract_html_comments(text: str) -> List[Tuple[int, str]]:
    """Extract all HTML comments as (1-based start_line, unescaped_body) tuples."""
    results: List[Tuple[int, str]] = []
    pos = 0
    line = 1
    n = len(text)
    while pos < n:
        start = text.find("<!--", pos)
        if start == -1:
            break
        line += text.count("\n", pos, start)
        body_start = start + 4
        end_std = text.find("-->", body_start)
        end_alt = text.find("--!>", body_start)
        candidates = [idx for idx in (end_std, end_alt) if idx != -1]
        if candidates:
            end = min(candidates)
            closer_len = 4 if end == end_alt else 3
            body = text[body_start:end]
            next_pos = end + closer_len
        else:
            body = text[body_start:]
            next_pos = n
        unescaped = html.unescape(body).strip()
        if unescaped:
            results.append((line, unescaped))
        line += text.count("\n", start, next_pos)
        pos = next_pos
    return results


def _find_hidden_block_spans(text: str) -> List[Tuple[int, int, int, str, str]]:
    """Locate hidden HTML elements as (start_idx, end_idx, start_line, inner_text, mechanism)."""
    hidden_classes, hidden_ids = _extract_hidden_css_selectors(text)
    spans: List[Tuple[int, int, int, str, str]] = []
    lower_text = text.lower()
    n = len(text)
    pos = 0
    line = 1
    while pos < n:
        lt = text.find("<", pos)
        if lt == -1:
            break
        line += text.count("\n", pos, lt)
        # Skip HTML comments cleanly.
        if text.startswith("<!--", lt):
            end_std = text.find("-->", lt + 4)
            end_alt = text.find("--!>", lt + 4)
            candidates = [idx for idx in (end_std, end_alt) if idx != -1]
            next_pos = (min(candidates) + (4 if min(candidates) == end_alt else 3)) if candidates else n
            line += text.count("\n", lt, next_pos)
            pos = next_pos
            continue
        gt = _find_tag_end(text, lt)
        if gt == -1:
            break
        tag_content = text[lt + 1 : gt].strip()
        if not tag_content or tag_content.startswith(("/", "!", "?")):
            line += text.count("\n", lt, gt + 1)
            pos = gt + 1
            continue
        m_tag = re.match(r"^([A-Za-z][A-Za-z0-9:-]*)(?:\s+(.*))?$", tag_content, re.DOTALL)
        if not m_tag:
            line += text.count("\n", lt, gt + 1)
            pos = gt + 1
            continue
        tag_name = m_tag.group(1).lower()
        attr_str = m_tag.group(2) or ""
        self_closing = tag_content.endswith("/")
        if tag_name in {"script", "style"}:
            close_tag = f"</{tag_name}>"
            close_idx = lower_text.find(close_tag, gt + 1)
            next_pos = (close_idx + len(close_tag)) if close_idx != -1 else n
            line += text.count("\n", lt, next_pos)
            pos = next_pos
            continue

        attrs = _parse_html_attributes(attr_str)
        mechanism: Optional[str] = None
        if "style" in attrs:
            mechanism = _css_hiding_reason(attrs["style"])
        if not mechanism and "hidden" in attrs and attrs["hidden"].lower() != "false":
            mechanism = "hidden attribute"
        if not mechanism and "class" in attrs and hidden_classes:
            elem_classes = {c.lower() for c in attrs["class"].split()}
            matched = elem_classes & hidden_classes
            if matched:
                mechanism = f"CSS class .{sorted(matched)[0]} (hidden)"
        if not mechanism and "id" in attrs and attrs["id"].lower() in hidden_ids:
            mechanism = f"CSS id #{attrs['id']} (hidden)"

        if mechanism and not self_closing:
            # Scan forward for the matching closing tag of the same tag_name.
            depth = 1
            scan = gt + 1
            open_pat = f"<{tag_name}"
            close_pat = f"</{tag_name}"
            block_end = n
            inner_end = n
            while scan < n and depth > 0:
                next_lt = lower_text.find("<", scan)
                if next_lt == -1:
                    break
                if lower_text.startswith(close_pat, next_lt):
                    after = next_lt + len(close_pat)
                    if after < n and (lower_text[after].isspace() or lower_text[after] == ">"):
                        close_gt = _find_tag_end(text, next_lt)
                        if close_gt == -1:
                            break
                        depth -= 1
                        if depth == 0:
                            inner_end = next_lt
                            block_end = close_gt + 1
                            break
                        scan = close_gt + 1
                        continue
                elif lower_text.startswith(open_pat, next_lt):
                    after = next_lt + len(open_pat)
                    if after < n and (lower_text[after].isspace() or lower_text[after] in "/>"):
                        nested_gt = _find_tag_end(text, next_lt)
                        if nested_gt == -1:
                            break
                        if not text[next_lt + 1 : nested_gt].rstrip().endswith("/"):
                            depth += 1
                        scan = nested_gt + 1
                        continue
                scan = next_lt + 1
            inner_plain = _strip_html_tags(text[gt + 1 : inner_end]).strip()
            if inner_plain:
                spans.append((lt, block_end, line, inner_plain, mechanism))
            line += text.count("\n", lt, block_end)
            pos = block_end
            continue

        line += text.count("\n", lt, gt + 1)
        pos = gt + 1
    return spans


def extract_display_none_blocks(text: str) -> List[Tuple[int, str]]:
    """Extract text hidden via display:none, visibility:hidden, opacity:0, or hidden attribute.

    Returns (1-based start_line, extracted_text) tuples.
    """
    return [(start_line, inner_text) for _, _, start_line, inner_text, _ in _find_hidden_block_spans(text)]


def _mask_hidden_regions(
    text: str,
    hidden_spans: Optional[Sequence[Tuple[int, int, int, str, str]]] = None,
) -> str:
    """Replace HTML comments and hidden HTML elements with spaces preserving line numbers."""
    chars = list(text)

    # Mask HTML comments.
    pos = 0
    n = len(text)
    while pos < n:
        start = text.find("<!--", pos)
        if start == -1:
            break
        end_std = text.find("-->", start + 4)
        end_alt = text.find("--!>", start + 4)
        candidates = [idx for idx in (end_std, end_alt) if idx != -1]
        if candidates:
            end = min(candidates) + (4 if min(candidates) == end_alt else 3)
        else:
            end = n
        for idx in range(start, end):
            if chars[idx] != "\n":
                chars[idx] = " "
        pos = end

    # Mask hidden HTML blocks (reusing precomputed spans when available).
    spans = _find_hidden_block_spans(text) if hidden_spans is None else hidden_spans
    for start, end, _, _, _ in spans:
        for idx in range(start, end):
            if chars[idx] != "\n":
                chars[idx] = " "

    return "".join(chars)


# Hidden-block anti-agent trap patterns.
HIDDEN_TRAP_PATTERNS: Tuple[Tuple[Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:if\s+you\s+are\s+(?:an?\s+)?|attention\s+|note\s+(?:to|for)\s+|for\s+|dear\s+)"
            r"(?:ai|llm|language\s+model|coding\s+agent|autonomous\s+agent|ai\s+agent|bot|"
            r"claude|chatgpt|gpt|copilot|codex|gemini)\b",
            re.IGNORECASE,
        ),
        "Hidden instruction directly addresses AI agents or LLMs.",
    ),
    (
        re.compile(
            r"\b(?:ai\s+agents?|llms?|language\s+models?|coding\s+agents?|automated\s+agents?|bots?)\b"
            r".{0,120}\b(?:do\s+not|don't|must\s+not|never|cannot|stop|abort|refuse|ignore|"
            r"disregard|close|forbidden|prohibited|banned|not\s+allowed|include|insert|mention|"
            r"write|append|canary|honeypot|flag)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Hidden directive restricts, traps, or instructs AI agents.",
    ),
    (
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b",
            re.IGNORECASE,
        ),
        "Hidden prompt-injection / instruction-override directive detected.",
    ),
    (
        re.compile(
            r"\b(?:include|insert|add|mention|put|write|append|start\s+with|end\s+with)\s+"
            r"(?:the\s+)?(?:exact\s+)?(?:secret\s+)?(?:word|phrase|codeword|keyword|canary|token|magic\s+word)\b",
            re.IGNORECASE,
        ),
        "Hidden canary/keyword honeypot instruction detected.",
    ),
    (
        re.compile(
            r"\b(?:honeypot|anti[- ]?agent|auto[- ]?clos\w*\s+(?:ai|agent|bot)|instant(?:ly)?\s+ban)\b",
            re.IGNORECASE,
        ),
        "Hidden anti-agent honeypot or auto-close trap detected.",
    ),
)

# Extra directive indicators for CSS display:none / hidden elements.
HIDDEN_ELEMENT_DIRECTIVE_RE = re.compile(
    r"\b(?:ai|llm|agent|bot|do\s+not|don't|must\s+not|never|abort|stop|ignore|"
    r"pull\s+request|issue|submit|contributor|instruction|prompt|canary|keyword|secret)\b",
    re.IGNORECASE,
)

# Negation guard so statements like "we do not ban AI" don't false-positive as bans.
BAN_NEGATION_GUARD_RE = re.compile(
    r"\b(?:do\s+not|don't|does\s+not|doesn't|no\s+longer|not)\s+(?:ban|prohibit|forbid|disallow)\s+(?:ai|llm)\b"
    r"|\bno\s+ban\s+on\s+(?:ai|llm)\b",
    re.IGNORECASE,
)

# Shared AI-term and noun-phrase regex fragments for compound policy wording.
_AI_MODIFIER = (
    r"(?:ai|llm|generative\s+ai|ai[- ]generated|ai[- ]assisted|"
    r"llm[- ]generated|machine[- ]generated|vibe[- ]?cod(?:ed|ing))"
)
_AI_MODIFIER_LIST = rf"{_AI_MODIFIER}(?:\s*(?:,|/|\bor\b|\band\b)\s*{_AI_MODIFIER})*"
_CONTRIB_NOUN = (
    r"(?:contributions?|pull\s+requests?|prs?|"
    r"issues?(?!\s+(?:descriptions?|text|prose|bod(?:y|ies)))|"
    r"code|patches?|submissions?|work|content|slop|tools?)"
)
_CONTRIB_NOUN_LIST = rf"{_CONTRIB_NOUN}(?:\s*(?:,|\bor\b|\band\b)\s*{_CONTRIB_NOUN})*"
_ALLOW_NOUN = (
    r"(?:contributions?|issues?|bug\s+reports?|reports?|prs?|pull\s+requests?|"
    r"work|testing|docs?|documentation(?:\s+fixes)?|policy[- ]pattern\s+suggestions?)"
)
_ALLOW_NOUN_LIST = rf"{_ALLOW_NOUN}(?:\s*(?:,|\bor\b|\band\b)\s*{_ALLOW_NOUN})*"

# Visible DENY rules.
DENY_RULES: Tuple[Tuple[str, Pattern[str], str], ...] = (
    (
        "AI_CONTRIBUTION_BAN",
        re.compile(
            rf"\b(?:no|zero)\s+(?:tolerance\s+for\s+)?{_AI_MODIFIER_LIST}\s+{_CONTRIB_NOUN_LIST}\b",
            re.IGNORECASE,
        ),
        "Policy explicitly prohibits AI-generated or AI-assisted contributions.",
    ),
    (
        "AI_CONTRIBUTION_BAN",
        re.compile(
            rf"\b{_AI_MODIFIER_LIST}(?:\s+{_CONTRIB_NOUN_LIST})?\s+"
            r"(?:are|is)\s+(?:strictly\s+)?(?:banned|prohibited|forbidden|disallowed|"
            r"not\s+accepted|not\s+permitted|not\s+allowed|rejected)\b",
            re.IGNORECASE,
        ),
        "Policy states AI contributions or AI tools are banned or not accepted.",
    ),
    (
        "AI_CONTRIBUTION_BAN",
        re.compile(
            r"\b(?:we\s+)?(?:do\s+not|don't|cannot|will\s+not|won't|never)\s+"
            rf"(?:accept|allow|permit|welcome|merge)\s+(?:any\s+)?{_AI_MODIFIER_LIST}\s+{_CONTRIB_NOUN_LIST}\b",
            re.IGNORECASE,
        ),
        "Policy states the project does not accept AI contributions.",
    ),
    (
        "AI_CONTRIBUTION_BAN",
        re.compile(
            r"\b(?:do\s+not|don't|never|must\s+not)\s+use\s+(?:any\s+)?"
            r"(?:ai|llms?|generative\s+ai|coding\s+agents?|chatgpt|claude|copilot)\s+"
            r"(?:to\s+(?:write|generate|create|submit|contribute)|when\s+contributing|for\s+contributions?|in\s+this\s+(?:repo|project))\b",
            re.IGNORECASE,
        ),
        "Policy forbids using AI tools for contributions.",
    ),
    (
        "AI_CONTRIBUTION_BAN",
        re.compile(
            r"\bstrictly\s+human[- ]only\s+(?:contributions?|project|repo|submissions?)\b"
            r"|\bban(?:s|ned|ning)?\s+(?:all\s+)?(?:ai|llm|vibe[- ]?coding)\s+(?:contributions?|code|prs?|pull\s+requests?|submissions?)\b",
            re.IGNORECASE,
        ),
        "Policy declares contributions strictly human-only or bans AI submissions.",
    ),
    (
        "VOUCH_GATE",
        re.compile(
            r"\bunvouched\s+(?:contributors?|outsiders?|users?|prs?|pull\s+requests?|issues?)"
            r".{0,80}\b(?:auto[- ]?clos\w*|automatically\s+clos\w*|reject\w*|block\w*|not\s+accepted)\b"
            r"|\bmust\s+be\s+vouched\s+(?:for\s+)?(?:before|to)\s+(?:contribut\w*|open\w*|submit\w*)\b"
            r"|\b(?:uses?|enforces?|requires?|listed\s+in|see)\s+`?(?:\.github/)?vouched\.td`?\b",
            re.IGNORECASE,
        ),
        "Policy enforces a maintainer vouch gate that blocks unvouched outsiders.",
    ),
)

# Visible DRAFT_ONLY rules (human prose required / no autonomous agents).
DRAFT_ONLY_RULES: Tuple[Tuple[str, Pattern[str], str], ...] = (
    (
        "HUMAN_PROSE_REQUIRED",
        re.compile(
            r"\bhuman\s+communication\s+must\s+remain\s+human\b"
            r"|\b(?:must\s+be|should\s+be)\s+(?:written\s+by\s+(?:a\s+)?human|human[- ]written|written\s+in\s+your\s+own\s+words)\b"
            r"|\bwrite\s+(?:all\s+)?(?:issues?|comments?|descriptions?|reports?|replies|messages?)\s+in\s+your\s+own\s+words\b"
            r"|\bin\s+your\s+own\s+words\b",
            re.IGNORECASE,
        ),
        "Policy requires human-written prose in the contributor's own words.",
    ),
    (
        "HUMAN_PROSE_REQUIRED",
        re.compile(
            r"\b(?:do\s+not|don't|never|must\s+not|no)\s+(?:post|submit|use|paste)?\s*"
            r"(?:ai|llm)[- ]?(?:generated|written|authored)\s+"
            r"(?:prose|comments?|descriptions?|messages?|replies|discussion|communication|text)\b",
            re.IGNORECASE,
        ),
        "Policy forbids AI-written comments, descriptions, or discussion text.",
    ),
    (
        "AUTONOMOUS_AGENT_BAN",
        re.compile(
            r"\b(?:no|ban(?:s|ned|ning)?|prohibit(?:s|ed)?|forbid(?:s|den)?|"
            r"do\s+not\s+(?:allow|permit|use)|not\s+allow(?:ed|ing)?)\s+"
            r"(?:fully\s+)?(?:autonomous|unattended|unsupervised)\s+(?:ai\s+)?agents?\b",
            re.IGNORECASE,
        ),
        "Policy forbids autonomous or unattended AI agents.",
    ),
    (
        "AUTONOMOUS_AGENT_BAN",
        re.compile(
            r"\b(?:ai\s+|coding\s+|automated\s+|autonomous\s+)?(?:agents?|assistants?|bots?)\s+"
            r"(?:must\s+not|may\s+not|cannot|should\s+not|are\s+not\s+(?:allowed|permitted)\s+to)\s+"
            r"(?:open|file|post|submit|create|comment|act\s+autonomously|send\s+anything|interact\s+directly)\b"
            r"|\b(?:do\s+not|don't|never)\s+let\s+(?:an?\s+)?(?:ai|llm|agent|bot)\s+"
            r"(?:open|file|post|submit|comment|act)\b",
            re.IGNORECASE,
        ),
        "Policy prohibits agents from posting, opening issues/PRs, or acting directly.",
    ),
    (
        "HUMAN_UNDERSTANDING_REQUIRED",
        re.compile(
            r"\b(?:must|expected\s+to)\s+(?:fully\s+)?understand\s+(?:and\s+(?:be\s+able\s+to\s+)?explain\s+)?"
            r"(?:every|all)\s+(?:line|change|code|contribution)\b"
            r"|\bexplain\s+(?:your\s+)?(?:proposed\s+)?changes?\s+in\s+your\s+own\s+words\b"
            r"|\bpersonally\s+understood,\s+tested,?\s+and\s+verified\b"
            r"|\bhuman[- ]in[- ]the[- ]loop\s+must\s+(?:fully\s+understand|review\s+and\s+(?:submit|post))\b",
            re.IGNORECASE,
        ),
        "Policy requires full human comprehension and direct human accountability/submission.",
    ),
)

# Visible ALLOW_WITH_DISCLOSURE rules.
ALLOW_RULES: Tuple[Tuple[str, Pattern[str], str], ...] = (
    (
        "AI_ALLOWED_WITH_DISCLOSURE",
        re.compile(
            rf"\b(?:ai|llm)[- ]?(?:assisted|generated|aided)\s+{_ALLOW_NOUN_LIST}\s+"
            r"(?:are|is)\s+(?:welcome|allowed|permitted|accepted|encouraged)\b",
            re.IGNORECASE,
        ),
        "Policy explicitly welcomes or permits AI-assisted contributions.",
    ),
    (
        "AI_ALLOWED_WITH_DISCLOSURE",
        re.compile(
            r"\b(?:we\s+)?(?:welcome|allow|permit|accept)s?\s+(?:transparent\s+|honest\s+|disclosed\s+)?"
            r"(?:ai|llm)[- ]?(?:assisted|aided)\b",
            re.IGNORECASE,
        ),
        "Policy allows AI-assisted contributions.",
    ),
    (
        "AI_ALLOWED_WITH_DISCLOSURE",
        re.compile(
            r"\b(?:please\s+|must\s+|should\s+)?disclose\s+(?:any\s+|your\s+)?"
            r"(?:ai|llm|generative\s+ai|coding\s+assistant)\b"
            r"|\b(?:ai|llm)\s+(?:usage|use|assistance|help)\s+(?:must|should)\s+be\s+disclosed\b"
            r"|\b(?:if\s+you\s+used?\s+(?:an?\s+)?(?:ai|llm|coding\s+assistant)|"
            r"when\s+using\s+(?:ai|llm)\s+tools?).{0,80}\b(?:disclose|note|mention|state|indicate)\b",
            re.IGNORECASE,
        ),
        "Policy permits AI assistance when disclosed.",
    ),
)

# Non-blocking operational hints surfaced alongside any verdict.
HINT_RULES: Tuple[Tuple[str, Pattern[str], str], ...] = (
    (
        "DISCLOSURE_FORMAT_HINT",
        re.compile(
            r"\b(?:assisted-by|generated-by|ai-disclosure|co-authored-by)\s*:"
            r"|\bdisclose\s+(?:which\s+)?(?:ai|llm)\s+(?:tool|model|assistant|usage|help)\b"
            r"|\b(?:ai|llm)\s+disclosure\b",
            re.IGNORECASE,
        ),
        "Specific AI disclosure format or note mentioned.",
    ),
    (
        "FORBIDDEN_TRAILER_HINT",
        re.compile(
            r"\b(?:do\s+not|don't|never|must\s+not|forbid\w*|strip|remove)\b.{0,60}"
            r"\b(?:co-authored-by|signed-off-by|ai\s+trailers?|attribution\s+trailers?)\b"
            r"|\b(?:co-authored-by|signed-off-by)\b.{0,60}\b(?:forbidden|prohibited|not\s+allowed|must\s+not)\b",
            re.IGNORECASE,
        ),
        "Policy restricts AI Co-Authored-By or Signed-off-by commit/comment trailers.",
    ),
    (
        "GOOD_FIRST_ISSUE_BAN_HINT",
        re.compile(
            r"\bgood\s+first\s+issue\b.{0,80}\b(?:no\s+ai|not\s+for\s+ai|humans?\s+only|forbidden|discouraged|do\s+not\s+use\s+ai)\b"
            r"|\b(?:do\s+not\s+use\s+ai|no\s+ai|forbid\w*\s+ai)\b.{0,80}\bgood\s+first\s+issue\b",
            re.IGNORECASE,
        ),
        "Policy reserves 'good first issue' tasks for humans without AI.",
    ),
    (
        "OUTSIDE_PR_CLOSED_HINT",
        re.compile(
            r"\b(?:outside|external)\s+(?:pull\s+requests?|prs?|code\s+(?:changes|contributions))\s+"
            r"(?:are\s+)?(?:closed|off|turned\s+off|disabled|not\s+accepted)\b"
            r"|\bpull\s+requests?\s+(?:are\s+)?(?:closed|turned\s+off|limited\s+to\s+collaborators)\b",
            re.IGNORECASE,
        ),
        "Outside pull requests are closed; participate via issues only.",
    ),
    (
        "DCO_OR_CLA_HINT",
        re.compile(
            r"\b(?:contributor\s+license\s+agreement|developer\s+certificate\s+of\s+origin|\bCLA\b|\bDCO\b)\b",
            re.IGNORECASE,
        ),
        "Repository mentions a CLA or DCO requirement.",
    ),
)


def _is_policy_path(rel_path: str) -> bool:
    """Return True if rel_path is a policy, agent-instruction, vouch, or template file."""
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/")
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    lower_parts = [p.lower() for p in parts]
    filename = lower_parts[-1]
    stem = Path(filename).stem
    ext = Path(filename).suffix

    # Check VOUCHED.td anywhere in root or .github/
    if filename == "vouched.td" and len(lower_parts) <= 2:
        return True

    # Issue or PR templates (inside .github/ISSUE_TEMPLATE/*, ISSUE_TEMPLATE/*, etc.)
    if len(lower_parts) >= 2 and lower_parts[-2] in {"issue_template", "pull_request_template"}:
        if lower_parts[0] in {".github", "issue_template", "pull_request_template"} and ext in TEMPLATE_EXTENSIONS:
            return True

    # Direct policy files in root, .github/, docs/, or doc/contributing/
    parent = "/".join(lower_parts[:-1])
    if parent in {"", ".github", "docs", "doc", "doc/contributing", "docs/contributing"}:
        if filename in POLICY_BASENAME_EXACT:
            return True
        if any(stem == prefix or stem.startswith(prefix + ".") for prefix in POLICY_STEM_PREFIXES):
            return ext in TEMPLATE_EXTENSIONS

    return False


def scan_content(file_path: str, content: str) -> List[Finding]:
    """Scan a single policy or template file and return all structured findings."""
    findings: List[Finding] = []
    norm_path = file_path.replace("\\", "/")
    basename = norm_path.rsplit("/", 1)[-1].lower()

    # 1. VOUCHED.td gate file check.
    if basename == "vouched.td":
        first_non_empty = next((ln.strip() for ln in content.splitlines() if ln.strip()), "(vouch list file)")
        findings.append(
            Finding(
                classification=VERDICT_DENY,
                rule_id="VOUCH_GATE",
                file_path=norm_path,
                line=1,
                excerpt=_clean_excerpt(first_non_empty),
                reason="VOUCHED.td file detected: repository requires prior maintainer vouching for outsiders.",
            )
        )
        return findings

    # 2. Scan hidden HTML comments (<!-- ... -->) for anti-agent traps.
    for line_no, comment_body in extract_html_comments(content):
        for pattern, reason in HIDDEN_TRAP_PATTERNS:
            if pattern.search(comment_body):
                findings.append(
                    Finding(
                        classification=VERDICT_DENY,
                        rule_id="HIDDEN_HTML_COMMENT_TRAP",
                        file_path=norm_path,
                        line=line_no,
                        excerpt=_clean_excerpt(f"<!-- {comment_body} -->"),
                        reason=f"HTML comment anti-agent trap: {reason}",
                    )
                )
                break

    # 3. Scan display:none / CSS-hidden / hidden-attribute blocks for anti-agent traps.
    hidden_spans = _find_hidden_block_spans(content)
    for _, _, line_no, hidden_text, mechanism in hidden_spans:
        matched_trap_reason: Optional[str] = None
        for pattern, reason in HIDDEN_TRAP_PATTERNS:
            if pattern.search(hidden_text):
                matched_trap_reason = reason
                break
        if matched_trap_reason or HIDDEN_ELEMENT_DIRECTIVE_RE.search(hidden_text):
            detail = matched_trap_reason or "Hidden element contains contributor/agent directive text."
            findings.append(
                Finding(
                    classification=VERDICT_DENY,
                    rule_id="HIDDEN_DISPLAY_NONE_TRAP",
                    file_path=norm_path,
                    line=line_no,
                    excerpt=_clean_excerpt(f"[{mechanism}] {hidden_text}"),
                    reason=f"Hidden HTML block ({mechanism}) anti-agent trap: {detail}",
                )
            )
        elif len(hidden_text.strip()) >= 15:
            findings.append(
                Finding(
                    classification=VERDICT_MANUAL_CHECK_REQUIRED,
                    rule_id="HIDDEN_CONTENT_WARNING",
                    file_path=norm_path,
                    line=line_no,
                    excerpt=_clean_excerpt(f"[{mechanism}] {hidden_text}"),
                    reason=f"Non-empty text hidden via {mechanism}; inspect manually before participating.",
                )
            )

    # 4. Scan visible text line-by-line (preserving exact 1-based line numbers).
    visible_text = _mask_hidden_regions(content, hidden_spans=hidden_spans)
    seen_line_rules: Set[Tuple[int, str]] = set()
    for line_no, raw_line in enumerate(visible_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue

        negated_ban = bool(BAN_NEGATION_GUARD_RE.search(line))

        for rule_id, pattern, reason in DENY_RULES:
            if rule_id == "AI_CONTRIBUTION_BAN" and negated_ban:
                continue
            if pattern.search(line) and (line_no, rule_id) not in seen_line_rules:
                seen_line_rules.add((line_no, rule_id))
                findings.append(
                    Finding(
                        classification=VERDICT_DENY,
                        rule_id=rule_id,
                        file_path=norm_path,
                        line=line_no,
                        excerpt=_clean_excerpt(line),
                        reason=reason,
                    )
                )

        for rule_id, pattern, reason in DRAFT_ONLY_RULES:
            if pattern.search(line) and (line_no, rule_id) not in seen_line_rules:
                seen_line_rules.add((line_no, rule_id))
                findings.append(
                    Finding(
                        classification=VERDICT_DRAFT_ONLY,
                        rule_id=rule_id,
                        file_path=norm_path,
                        line=line_no,
                        excerpt=_clean_excerpt(line),
                        reason=reason,
                    )
                )

        for rule_id, pattern, reason in ALLOW_RULES:
            if pattern.search(line) and (line_no, rule_id) not in seen_line_rules:
                seen_line_rules.add((line_no, rule_id))
                findings.append(
                    Finding(
                        classification=VERDICT_ALLOW_WITH_DISCLOSURE,
                        rule_id=rule_id,
                        file_path=norm_path,
                        line=line_no,
                        excerpt=_clean_excerpt(line),
                        reason=reason,
                    )
                )

        for rule_id, pattern, reason in HINT_RULES:
            if pattern.search(line) and (line_no, rule_id) not in seen_line_rules:
                seen_line_rules.add((line_no, rule_id))
                findings.append(
                    Finding(
                        classification="HINT",
                        rule_id=rule_id,
                        file_path=norm_path,
                        line=line_no,
                        excerpt=_clean_excerpt(line),
                        reason=reason,
                    )
                )

    return findings


def scan_documents(
    documents: Sequence[ScannedFile],
    target: str = "<memory>",
    fetch_warnings: Sequence[str] = (),
) -> PolicyReport:
    """Classify a collection of scanned policy files using strictest-rule precedence."""
    scanned_paths: List[str] = []
    policy_findings: List[Finding] = []
    hints: List[Finding] = []

    for doc in documents:
        scanned_paths.append(doc.path)
        for item in scan_content(doc.path, doc.content):
            if item.classification == "HINT":
                hints.append(item)
            else:
                policy_findings.append(item)

    classes = {f.classification for f in policy_findings}
    if VERDICT_DENY in classes:
        verdict = VERDICT_DENY
    elif VERDICT_DRAFT_ONLY in classes:
        verdict = VERDICT_DRAFT_ONLY
    elif VERDICT_MANUAL_CHECK_REQUIRED in classes:
        verdict = VERDICT_MANUAL_CHECK_REQUIRED
    elif VERDICT_ALLOW_WITH_DISCLOSURE in classes:
        verdict = VERDICT_ALLOW_WITH_DISCLOSURE
    else:
        verdict = VERDICT_MANUAL_CHECK_REQUIRED

    warnings = list(fetch_warnings)
    if not scanned_paths:
        warnings.append("No policy, contributing, agent, vouch, or template files were found.")
    elif verdict == VERDICT_MANUAL_CHECK_REQUIRED and VERDICT_MANUAL_CHECK_REQUIRED not in classes:
        warnings.append(
            "No explicit AI contribution policy was matched; read the repository guidelines manually before acting."
        )

    return PolicyReport(
        target=target,
        verdict=verdict,
        scanned_files=scanned_paths,
        findings=policy_findings,
        hints=hints,
        warnings=warnings,
    )


def _collect_local_policy_files(root: Path, prefix: str = "") -> List[ScannedFile]:
    """Collect candidate policy files from a local repository directory."""
    docs: List[ScannedFile] = []
    if not root.exists() or not root.is_dir():
        return docs

    candidate_dirs = [
        root,
        root / ".github",
        root / ".github" / "ISSUE_TEMPLATE",
        root / ".github" / "PULL_REQUEST_TEMPLATE",
        root / "ISSUE_TEMPLATE",
        root / "PULL_REQUEST_TEMPLATE",
        root / "docs",
        root / "doc",
        root / "doc" / "contributing",
        root / "docs" / "contributing",
    ]
    seen: Set[Path] = set()
    for directory in candidate_dirs:
        if not directory.is_dir():
            continue
        for entry in sorted(directory.iterdir(), key=lambda p: p.name.lower()):
            if not entry.is_file():
                continue
            resolved = entry.resolve()
            if resolved in seen:
                continue
            rel = entry.relative_to(root).as_posix()
            if not _is_policy_path(rel):
                continue
            seen.add(resolved)
            try:
                raw_bytes = entry.read_bytes()[:MAX_FILE_BYTES]
                text = raw_bytes.decode("utf-8", errors="replace")
            except OSError:
                continue
            display_path = f"{prefix}{rel}" if prefix else rel
            docs.append(ScannedFile(path=display_path, content=text, source="local"))
    return docs


def scan_local_dir(
    local_dir: Union[str, Path],
    org_dir: Optional[Union[str, Path]] = None,
) -> PolicyReport:
    """Scan a local repository checkout (and optional local org .github mirror)."""
    root = Path(local_dir)
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Local directory does not exist: {root}")

    docs = _collect_local_policy_files(root)
    warnings: List[str] = []
    if org_dir is not None:
        org_path = Path(org_dir)
        if not org_path.exists() or not org_path.is_dir():
            warnings.append(f"Org directory does not exist: {org_path}")
        else:
            docs.extend(_collect_local_policy_files(org_path, prefix="org/.github/"))

    return scan_documents(docs, target=str(root), fetch_warnings=warnings)


def _gh_api_json_status(endpoint: str, timeout: int = 15) -> Tuple[Optional[object], Optional[int]]:
    """Run `gh api <endpoint>` and return (parsed_json, status_hint)."""
    try:
        proc = subprocess.run(
            ["gh", "api", endpoint],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None
    if proc.returncode != 0:
        err = (proc.stderr or "") + (proc.stdout or "")
        if "HTTP 404" in err or '"status": "404"' in err or "Not Found" in err:
            return None, 404
        return None, None
    if not proc.stdout.strip():
        return None, None
    try:
        return json.loads(proc.stdout), 200
    except json.JSONDecodeError:
        return None, None


def _gh_api_json(endpoint: str, timeout: int = 15) -> Optional[object]:
    """Run `gh api <endpoint>` and parse JSON output, returning None on 404/error."""
    data, _ = _gh_api_json_status(endpoint, timeout=timeout)
    return data


def _gh_fetch_raw(repo: str, branch: str, path: str, timeout: int = 15) -> Optional[str]:
    """Fetch a raw file from GitHub using `gh api` with raw accept header."""
    encoded_path = urllib.parse.quote(path, safe="/")
    endpoint = f"repos/{repo}/contents/{encoded_path}?ref={urllib.parse.quote(branch, safe='')}"
    try:
        proc = subprocess.run(
            ["gh", "api", "-H", "Accept: application/vnd.github.raw+json", endpoint],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout[:MAX_FILE_BYTES].decode("utf-8", errors="replace")


def _http_get_bytes_status(
    url: str,
    accept: Optional[str] = None,
    timeout: int = 15,
) -> Tuple[Optional[bytes], Optional[int]]:
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(MAX_FILE_BYTES), resp.status
    except urllib.error.HTTPError as exc:
        return None, exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None


def _http_get_bytes(url: str, accept: Optional[str] = None, timeout: int = 15) -> Optional[bytes]:
    raw, status = _http_get_bytes_status(url, accept=accept, timeout=timeout)
    return raw if status == 200 else None


def _http_api_json_status(endpoint: str, timeout: int = 15) -> Tuple[Optional[object], Optional[int]]:
    url = f"https://api.github.com/{endpoint.lstrip('/')}"
    raw, status = _http_get_bytes_status(url, accept="application/vnd.github+json", timeout=timeout)
    if raw is None or status != 200:
        return None, status
    try:
        return json.loads(raw.decode("utf-8", errors="replace")), 200
    except json.JSONDecodeError:
        return None, None


def _http_api_json(endpoint: str, timeout: int = 15) -> Optional[object]:
    data, _ = _http_api_json_status(endpoint, timeout=timeout)
    return data


def _http_fetch_raw(repo: str, branch: str, path: str, timeout: int = 15) -> Optional[str]:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_branch = urllib.parse.quote(branch, safe="")
    url = f"https://raw.githubusercontent.com/{repo}/{encoded_branch}/{encoded_path}"
    raw = _http_get_bytes(url, timeout=timeout)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def _list_remote_policy_paths(
    repo: str,
    branch: str,
    use_gh: bool,
    timeout: int,
) -> Optional[List[str]]:
    """List candidate policy paths via GitHub Contents API, or None if unavailable.

    Prunes missing subdirectories using the root and first-level directory listings
    and aligns checked directories (including `doc/` and `docs/contributing/`) with
    `scan_local_dir`.
    """
    api_json = _gh_api_json if use_gh else _http_api_json
    ref_q = urllib.parse.quote(branch, safe="")

    def _fetch_dir(directory: str) -> Optional[List[object]]:
        suffix = f"/{urllib.parse.quote(directory, safe='/')}" if directory else ""
        data = api_json(f"repos/{repo}/contents{suffix}?ref={ref_q}", timeout=timeout)
        return data if isinstance(data, list) else None

    root_data = _fetch_dir("")
    if root_data is None:
        return None

    discovered: List[str] = []

    def _collect(entries: Sequence[object]) -> Dict[str, str]:
        subdirs: Dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get("type")
            path = entry.get("path")
            name = entry.get("name")
            if entry_type == "file" and isinstance(path, str) and _is_policy_path(path):
                discovered.append(path)
            elif entry_type == "dir" and isinstance(name, str) and isinstance(path, str):
                subdirs[name.lower()] = path
        return subdirs

    root_dirs = _collect(root_data)

    # Level-1 directories to inspect only if they actually exist in root.
    level1_targets = (".github", "issue_template", "pull_request_template", "docs", "doc")
    level1_existing = [(key, root_dirs[key]) for key in level1_targets if key in root_dirs]

    nested_plan = {
        ".github": ("issue_template", "pull_request_template"),
        "docs": ("contributing",),
        "doc": ("contributing",),
    }
    level2_dirs: List[str] = []

    if level1_existing:
        with ThreadPoolExecutor(max_workers=min(6, len(level1_existing))) as pool:
            futures = [(key, pool.submit(_fetch_dir, dir_path)) for key, dir_path in level1_existing]
            for key, future in futures:
                entries = future.result()
                if entries is None:
                    continue
                child_dirs = _collect(entries)
                for child_key in nested_plan.get(key, ()):
                    if child_key in child_dirs:
                        level2_dirs.append(child_dirs[child_key])

    if level2_dirs:
        with ThreadPoolExecutor(max_workers=min(6, len(level2_dirs))) as pool:
            for entries in pool.map(_fetch_dir, level2_dirs):
                if entries is not None:
                    _collect(entries)

    return sorted(set(discovered))


def _fetch_single_github_repo(
    repo: str,
    branch: Optional[str],
    source: str,
    prefix: str,
    timeout: int,
    optional_repo: bool = False,
) -> Tuple[List[ScannedFile], List[str]]:
    """Fetch policy files for one GitHub repository."""
    warnings: List[str] = []
    use_gh = False
    if source in {"auto", "gh"} and shutil.which("gh"):
        use_gh = True
    elif source == "gh":
        warnings.append("Requested --source gh, but 'gh' CLI was not found on PATH.")
        return [], warnings

    api_status = _gh_api_json_status if use_gh else _http_api_json_status
    fetch_raw = _gh_fetch_raw if use_gh else _http_fetch_raw

    resolved_branch = branch
    if not resolved_branch:
        meta, status = api_status(f"repos/{repo}", timeout=timeout)
        if status == 404:
            if not optional_repo:
                warnings.append(f"Repository {repo} was not found (HTTP 404).")
            return [], warnings
        if isinstance(meta, dict) and isinstance(meta.get("default_branch"), str):
            resolved_branch = meta["default_branch"]
        elif source == "auto" and use_gh:
            # gh may be unauthenticated or offline; try unauthenticated REST API next.
            use_gh = False
            api_status = _http_api_json_status
            fetch_raw = _http_fetch_raw
            meta, status = api_status(f"repos/{repo}", timeout=timeout)
            if status == 404:
                if not optional_repo:
                    warnings.append(f"Repository {repo} was not found (HTTP 404).")
                return [], warnings
            if isinstance(meta, dict) and isinstance(meta.get("default_branch"), str):
                resolved_branch = meta["default_branch"]

    branches_to_try = [resolved_branch] if resolved_branch else ["main", "master"]
    docs: List[ScannedFile] = []

    for candidate_branch in branches_to_try:
        paths = _list_remote_policy_paths(repo, candidate_branch, use_gh=use_gh, timeout=timeout)
        if paths is not None:
            if paths:
                with ThreadPoolExecutor(max_workers=min(8, len(paths))) as pool:
                    contents = list(
                        pool.map(
                            lambda p: fetch_raw(repo, candidate_branch, p, timeout=timeout),
                            paths,
                        )
                    )
                for path, content in zip(paths, contents):
                    if content is not None:
                        docs.append(
                            ScannedFile(
                                path=f"{prefix}{path}",
                                content=content,
                                source="gh" if use_gh else "raw",
                            )
                        )
            return docs, warnings

        # Directory listing unavailable (e.g., API rate limit): probe raw URLs in parallel.
        with ThreadPoolExecutor(max_workers=min(8, len(RAW_FALLBACK_PATHS))) as pool:
            probed = list(
                pool.map(
                    lambda p: _http_fetch_raw(repo, candidate_branch, p, timeout=timeout),
                    RAW_FALLBACK_PATHS,
                )
            )
        probed_any = False
        for path, content in zip(RAW_FALLBACK_PATHS, probed):
            if content is not None:
                probed_any = True
                docs.append(ScannedFile(path=f"{prefix}{path}", content=content, source="raw"))
        if probed_any:
            warnings.append(
                f"Used direct raw-URL probes for {repo}@{candidate_branch}; custom template filenames may require manual review."
            )
            return docs, warnings

    return docs, warnings


def scan_github_repo(
    repo: str,
    branch: Optional[str] = None,
    source: str = "auto",
    include_org: bool = True,
    timeout: int = 15,
) -> PolicyReport:
    """Fetch and classify policy files for a live GitHub repository (owner/name)."""
    if not REPO_SLUG_RE.match(repo):
        raise ValueError(f"Invalid GitHub repository slug '{repo}'. Expected 'owner/repo'.")
    if source not in {"auto", "gh", "raw"}:
        raise ValueError(f"Invalid source '{source}'. Expected 'auto', 'gh', or 'raw'.")

    owner, name = repo.split("/", 1)
    docs, warnings = _fetch_single_github_repo(
        repo=repo,
        branch=branch,
        source=source,
        prefix="",
        timeout=timeout,
        optional_repo=False,
    )

    if include_org and name != ".github":
        org_repo = f"{owner}/.github"
        org_docs, org_warnings = _fetch_single_github_repo(
            repo=org_repo,
            branch=None,
            source=source,
            prefix=f"{org_repo}/",
            timeout=timeout,
            optional_repo=True,
        )
        docs.extend(org_docs)
        warnings.extend(org_warnings)

    return scan_documents(docs, target=repo, fetch_warnings=warnings)


def format_report_text(report: PolicyReport) -> str:
    """Format a PolicyReport as clear, plain-text terminal output."""
    lines: List[str] = [
        f"Target:  {report.target}",
        f"Verdict: {report.verdict}",
        f"Scanned: {len(report.scanned_files)} file(s)",
    ]
    if report.scanned_files:
        for path in report.scanned_files:
            lines.append(f"  - {path}")

    if report.findings:
        lines.append("")
        lines.append("Policy findings:")
        for f in report.findings:
            lines.append(f"  [{f.classification}] {f.rule_id} at {f.file_path}:{f.line}")
            lines.append(f"    Reason:  {f.reason}")
            lines.append(f"    Excerpt: {f.excerpt}")

    if report.hints:
        lines.append("")
        lines.append("Disclosure & workflow hints:")
        for h in report.hints:
            lines.append(f"  [HINT] {h.rule_id} at {h.file_path}:{h.line}")
            lines.append(f"    Note:    {h.reason}")
            lines.append(f"    Excerpt: {h.excerpt}")

    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in report.warnings:
            lines.append(f"  - {w}")

    return "\n".join(lines)


def _strict_exit_code(verdict: str) -> int:
    return {
        VERDICT_ALLOW_WITH_DISCLOSURE: 0,
        VERDICT_DENY: 2,
        VERDICT_DRAFT_ONLY: 3,
        VERDICT_MANUAL_CHECK_REQUIRED: 4,
    }.get(verdict, 1)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_repo_policy.py",
        description=(
            "Pre-flight scanner for repository AI contribution policies, "
            "hidden HTML/CSS anti-agent traps, and VOUCHED.td gates."
        ),
    )
    parser.add_argument(
        "repo",
        nargs="?",
        help="GitHub repository slug (owner/name) to scan live.",
    )
    parser.add_argument(
        "--repo",
        dest="repo_flag",
        help="GitHub repository slug (owner/name) to scan live (alternative to positional argument).",
    )
    parser.add_argument(
        "--local-dir",
        help="Offline mode: scan policy and template files inside a local directory.",
    )
    parser.add_argument(
        "--org-dir",
        help="Optional local directory mirroring org-level .github policy files (used with --local-dir).",
    )
    parser.add_argument(
        "--branch",
        help="Override target GitHub branch (defaults to repository default branch).",
    )
    parser.add_argument(
        "--source",
        choices=("auto", "gh", "raw"),
        default="auto",
        help="Fetch method for live GitHub scans (default: auto).",
    )
    parser.add_argument(
        "--no-org",
        action="store_true",
        help="Skip checking the owner/.github org-level repository during live GitHub scans.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Network/CLI timeout in seconds for live GitHub scans (default: 15).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON instead of plain text.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Return non-zero exit codes by verdict: "
            "0=ALLOW_WITH_DISCLOSURE, 2=DENY, 3=DRAFT_ONLY, 4=MANUAL_CHECK_REQUIRED."
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    repo_slug = args.repo_flag or args.repo
    if bool(args.local_dir) == bool(repo_slug):
        parser.error("Provide either a GitHub repo slug (owner/name) OR --local-dir PATH.")

    try:
        if args.local_dir:
            report = scan_local_dir(args.local_dir, org_dir=args.org_dir)
        else:
            report = scan_github_repo(
                repo=repo_slug,
                branch=args.branch,
                source=args.source,
                include_org=not args.no_org,
                timeout=args.timeout,
            )
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report_text(report))

    if args.strict:
        return _strict_exit_code(report.verdict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
