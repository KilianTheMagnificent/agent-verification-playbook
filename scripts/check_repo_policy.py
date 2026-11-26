#!/usr/bin/env python3
"""Pre-flight repository AI-policy scanner (Python 3.9+ stdlib only).

Fetches or reads repository policy files (CONTRIBUTING.*, AI_POLICY.*,
AGENTS.md, CLAUDE.md, .github/VOUCHED.td, issue and PR templates, relevant
vouch and slop workflows, and org-level .github equivalents), inspects
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
import http.client
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

USER_AGENT = "agent-verification-playbook-policy-scanner/0.2.0"
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
MAX_API_BYTES = 2 * 1024 * 1024  # Contents listings can be larger than policy files.
CONTENTS_DIRECTORY_LIMIT = 1000
FetchStatus = Union[int, str]

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
    ".github/workflows/vouch-check-pr.yml",
    ".github/workflows/on-slop.yml",
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


# A formatting-only reminder can address agents without imposing a contribution rule.
FORMATTING_COMMENT_RE = re.compile(
    r"ai\s+agents?:\s+(?:please\s+)?(?:do\s+not|don['’]t)\s+hard[- ]wrap\s+paragraphs"
    r"(?:[.;]\s+github renders every line break, so keep each paragraph on a single line)?[.!]?",
    re.IGNORECASE,
)

VOUCH_SETTING_RE = re.compile(
    r"""^\s*require-vouch:\s*(?P<quote>["']?)(?P<setting>true|false)(?P=quote)\s*(?:#.*)?$""",
    re.IGNORECASE,
)
VOUCH_OPTIONAL_RE = re.compile(
    r"\bbeing absent from this file blocks nothing\b",
    re.IGNORECASE,
)

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
            r"(?:the\s+)?(?:exact\s+)?(?:secret\s+)?(?:word|phrase|codeword|keyword|canary|token|magic\s+word)\b"
            r"|\b(?:include|insert|add|append)\s+(?:the\s+)?(?::[a-z0-9_+-]+:|ASLOP-PR-VERIFY\b)",
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
    r"code|patches?|submissions?|work|content|tools?)"
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
            rf"\b(?:no|zero)\s+(?:tolerance\s+for\s+)?{_AI_MODIFIER_LIST}\s+{_CONTRIB_NOUN_LIST}\b"
            r"(?!\s+were\s+used)\b"
            r"|^[-*]\s+\[[ x]\]\s+no\s+ai\s+tools\s+were\s+used\b",
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
        "AI_CONTRIBUTION_BAN",
        re.compile(
            r"\bcontributions?\s+must\s+not\s+include\s+content\s+generated\s+by\s+"
            r"(?:large\s+language\s+models?|llms?|ai)\b",
            re.IGNORECASE,
        ),
        "Policy prohibits contributions containing AI-generated content.",
    ),
    (
        "AUTONOMOUS_AGENT_BAN",
        re.compile(
            r"\baccounts\s+controlled\s+by\s+autonomous\s+(?:ai\s+)?(?:bots?|agents?)\s+"
            r"(?:are\s+)?(?:forbidden|banned|prohibited|not\s+allowed)\b"
            r"|\b(?:do\s+not|don't)\s+allow\s+autonomous\s+agents\s+to\s+be\s+used\s+for\s+"
            r"contributing[^.!?]{0,200}[.!?]\s+we\s+will\s+close\b"
            r"|\babsolutely\s+no\s+unsupervised\s+agentic\s+tools\b",
            re.IGNORECASE,
        ),
        "Policy explicitly forbids autonomous agent accounts or closes autonomous submissions.",
    ),
    (
        "VOUCH_GATE",
        re.compile(
            r"\bunvouched\s+(?:contributors?|outsiders?|users?|prs?|pull\s+requests?|issues?)\b"
            r"(?:(?!\b(?:not|never|no|nothing)\b|n['’]t\b)[^.!?\n]){0,80}?"
            r"\b(?:auto[- ]?clos\w*|automatically\s+clos\w*|closed|rejected|blocked|not\s+accepted)\b"
            r"|\bmust\s+be\s+vouched\s+(?:for\s+)?(?:before|to)\s+(?:contribut\w*|open\w*|submit\w*)\b"
            r"|\b(?:must|need\s+to)\s+be\s+listed\s+in\s+`?(?:\.github/)?vouched\.td\b",
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
            r"|\bin\s+your\s+own\s+words\b"
            r"|\b(?:must|should|expected\s+to)\s+be\s+written\s+in\s+"
            r"(?:the\s+contributor['’]s|your)\s+own\s+(?:words|voice)\b"
            r"|\bplease\s+use\s+(?:simple,\s+)?human[- ]written\s+(?:english|prose)\b"
            r"|\b(?:comments?|replies)\b[^.!?]{0,80}\bmay\s+not\s+be\s+written\s+with\s+"
            r"(?:llms?|ai)\b"
            r"|\bdo\s+not\s+paste\s+(?:llm|ai)\s+output\s+verbatim\b"
            r"|\bwrite\s+(?:the|your)\s+(?:pr|pull\s+request|issue)\s+description\s+yourself\b"
            r"|\bplease\s+use\s+your\s+own\s+words\b"
            r"|\b(?:do\s+not|don't)\s+use\s+(?:an?\s+)?(?:llms?|ai)\s+to\s+"
            r"(?:fill\s+in\s+templates?|respond\s+to\s+(?:review\s+)?comments?)\b"
            r"|\bplease\s+avoid\s+using\s+(?:llms?|ai)\s+to\s+generate\s+the\s+description\s+text\b"
            r"|\b(?:do\s+not|don't)\s+(?:push|post|submit)\s+(?:llms?|ai)[- ]generated\s+"
            r"(?:issues?|pull[- ]requests?|prs?)\b",
            re.IGNORECASE,
        ),
        "Policy requires human-written prose in the contributor's own words.",
    ),
    (
        "HUMAN_PROSE_REQUIRED",
        re.compile(
            r"\b(?:do\s+not|don't|never|must\s+not|no)\s+(?:post|submit|use|paste)?\s*"
            r"(?:ai|llm)[- ]?(?:generated|written|authored)\s+"
            r"(?:prose|(?:review\s+)?comments?|descriptions?|messages?|replies|discussion|communication|text)\b",
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
            r"(?:open|file|post|submit|comment|act)\b"
            r"|\b(?:will\s+not|won't)\s+accept\s+(?:prs?|pull\s+requests?)\s+"
            r"(?:opened|submitted)(?:\s+or\s+submitted)?\s+by\s+ai\s+agents?\b"
            r"|\b(?:must|should)\s+be\s+opened\s+by\s+a\s+(?:real\s+person|human)\b"
            r"|\bthe\s+human\s+submitter\s+is\s+responsible\s+for\s+the\s+entire\s+contribution\b",
            re.IGNORECASE,
        ),
        "Policy prohibits agents from posting, opening issues/PRs, or acting directly.",
    ),
    (
        "HUMAN_UNDERSTANDING_REQUIRED",
        re.compile(
            r"\b(?:must|expected\s+to)\s+(?:fully\s+)?understand\s+(?:and\s+(?:be\s+able\s+to\s+)?explain\s+)?"
            r"(?:every|all)\s+(?:line|change|code|contribution)\b"
            r"|^[-*]\s+understand\s+every\s+change\s+you\s+submit,?\s+and\s+be\s+able\s+to\s+explain\s+it\b"
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
            r"|\busing\s+(?:a\s+model\s+to\s+help|ai\s+to\s+write\s+code)\s+is\s+fine\b"
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
        "HUMAN_ATTESTATION_HINT",
        re.compile(
            r"^[-*]\s+label:\s*[\"']?i\s*\(a\s+human\)\s+examined\b[^.!?]{0,120}\b"
            r"(?:wrote\s+or\s+reviewed)\b",
            re.IGNORECASE,
        ),
        "Issue form asks the submitter to attest to human review of the report.",
    ),
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


# These directives can span multiple lines in Markdown.
TURN_OFF_AUTONOMOUS_AGENT_RE = re.compile(
    r"\bagent\s+filing\s+(?:issues?|prs?|pull\s+requests?)(?:\s+or\s+(?:prs?|pull\s+requests?))?\s+"
    r"against\s+this\s+repository\s+autonomously,?\s+please\s+turn\s+it\s+off\b",
    re.IGNORECASE,
)


EXTERNAL_AI_POLICY_RE = re.compile(
    r"\b(?:follow(?:s)?|adopts?)\s+(?:the\s+)?same\s+"
    r"(?:ai\s+usage\s+conventions|\[(?:llm|ai)\s+usage\s+policy\])\s+as\s+[^\n]+"
    r"|\b(?:please\s+)?review\s+https://[^\s<>]+#(?:llm-and-ai-policy|ai-policy)\b",
    re.IGNORECASE,
)


VOUCH_CHECK_USE_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*[\"']?mitchellh/vouch/action/check-[a-z-]+@",
    re.IGNORECASE | re.MULTILINE,
)


def _workflow_vouch_optional(content: str) -> Optional[bool]:
    """True if every vouch check is explicitly optional, False if any can gate, None if none."""
    settings = [required for _, _, required in _vouch_workflow_settings(content)]
    uses = len(VOUCH_CHECK_USE_RE.findall(content))
    if not settings and not uses:
        return None
    # The action's require-vouch input defaults to true, so an unset check is a gate.
    return not any(settings) and len(settings) >= uses


def _is_policy_workflow(path: str) -> bool:
    parent, _, filename = path.lower().rpartition("/")
    return (
        (parent == ".github/workflows" or parent.endswith("/.github/workflows"))
        and Path(filename).suffix in {".yml", ".yaml"}
        and re.search(r"(?:^|[-_])(?:vouch|slop)(?=[-_.])", filename) is not None
    )


def _vouch_scope(path: str) -> str:
    parent = path.rpartition("/")[0]
    for suffix in (".github/workflows", ".github"):
        if parent == suffix:
            return ""
        if parent.endswith("/" + suffix):
            return parent[: -len(suffix) - 1]
    return parent


def _vouch_workflow_settings(content: str) -> Iterable[Tuple[int, str, bool]]:
    for line_no, line in enumerate(content.splitlines(), start=1):
        match = VOUCH_SETTING_RE.fullmatch(line)
        if match:
            yield line_no, line, match.group("setting").lower() == "true"


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

    if _is_policy_workflow(norm):
        return True

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


def scan_content(
    file_path: str, content: str, *, optional_vouch_list: bool = False
) -> List[Finding]:
    """Scan a single policy or template file and return all structured findings."""
    findings: List[Finding] = []
    norm_path = file_path.replace("\\", "/")
    basename = norm_path.rsplit("/", 1)[-1].lower()

    # 1. Check vouch settings and lists. Workflow names never establish a policy.
    if _is_policy_workflow(norm_path):
        return [
            Finding(
                VERDICT_DENY, "VOUCH_GATE", norm_path, line_no, _clean_excerpt(line),
                "Workflow requires contributors to be vouched.",
            )
            for line_no, line, required in _vouch_workflow_settings(content)
            if required
        ]
    if basename == "vouched.td":
        prose = " ".join(line.lstrip("# ").strip() for line in content.splitlines())
        if optional_vouch_list or VOUCH_OPTIONAL_RE.search(prose):
            return []
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
        if FORMATTING_COMMENT_RE.fullmatch(" ".join(comment_body.split())):
            continue
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
        else:
            # Templates often hide ordinary contributor instructions in HTML comments.
            plain_comment = comment_body.replace("**", "").replace("__", "")
            for rule_id, pattern, reason in DRAFT_ONLY_RULES:
                if rule_id == "HUMAN_PROSE_REQUIRED":
                    match = pattern.search(plain_comment)
                    if match:
                        findings.append(
                            Finding(
                                VERDICT_DRAFT_ONLY, rule_id, norm_path, line_no,
                                _clean_excerpt(match.group()),
                                f"HTML template comment: {reason}",
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

    # 4. Scan visible policy text, preserving exact 1-based line numbers.
    visible_text = _mask_hidden_regions(content, hidden_spans=hidden_spans)
    wrapped_rules = (
        (
            TURN_OFF_AUTONOMOUS_AGENT_RE, VERDICT_DRAFT_ONLY, "AUTONOMOUS_AGENT_BAN",
            "Policy requires contributors to turn off agents that file issues or PRs autonomously.",
        ),
        (
            EXTERNAL_AI_POLICY_RE, VERDICT_MANUAL_CHECK_REQUIRED, "EXTERNAL_AI_POLICY",
            "Repository points to an external AI policy that requires manual review.",
        ),
    )
    for pattern, verdict, rule_id, reason in wrapped_rules:
        line_no, previous_start = 1, 0
        for match in pattern.finditer(visible_text):
            line_no += visible_text.count("\n", previous_start, match.start())
            previous_start = match.start()
            findings.append(Finding(verdict, rule_id, norm_path, line_no, _clean_excerpt(match.group()), reason))

    seen_line_rules: Set[Tuple[int, str]] = set()
    for line_no, raw_line in enumerate(visible_text.splitlines(), start=1):
        line = raw_line.strip()
        # Emphasis can split a policy expression into multiple Markdown spans.
        plain = line.replace("**", "").replace("__", "")
        if not line:
            continue

        negated_ban = bool(BAN_NEGATION_GUARD_RE.search(plain))

        for rule_id, pattern, reason in DENY_RULES:
            if rule_id == "AI_CONTRIBUTION_BAN" and negated_ban:
                continue
            if pattern.search(plain) and (line_no, rule_id) not in seen_line_rules:
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
            if pattern.search(plain) and (line_no, rule_id) not in seen_line_rules:
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
            if pattern.search(plain) and (line_no, rule_id) not in seen_line_rules:
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
            if pattern.search(plain) and (line_no, rule_id) not in seen_line_rules:
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

    vouch_states: Dict[str, List[bool]] = {}
    for doc in documents:
        if _is_policy_workflow(doc.path):
            state = _workflow_vouch_optional(doc.content)
            if state is not None:
                vouch_states.setdefault(_vouch_scope(doc.path), []).append(state)
    optional_vouch_scopes = {scope for scope, states in vouch_states.items() if all(states)}
    for doc in documents:
        scanned_paths.append(doc.path)
        for item in scan_content(
            doc.path, doc.content, optional_vouch_list=_vouch_scope(doc.path) in optional_vouch_scopes
        ):
            if item.classification == "HINT":
                hints.append(item)
            else:
                policy_findings.append(item)

    classes = {f.classification for f in policy_findings}
    if VERDICT_DENY in classes:
        verdict = VERDICT_DENY
    elif VERDICT_DRAFT_ONLY in classes:
        verdict = VERDICT_DRAFT_ONLY
    elif fetch_warnings or VERDICT_MANUAL_CHECK_REQUIRED in classes:
        verdict = VERDICT_MANUAL_CHECK_REQUIRED
    elif VERDICT_ALLOW_WITH_DISCLOSURE in classes:
        verdict = VERDICT_ALLOW_WITH_DISCLOSURE
    else:
        verdict = VERDICT_MANUAL_CHECK_REQUIRED

    warnings = list(fetch_warnings)
    if not scanned_paths and not warnings:
        warnings.append("No policy, contributing, agent, vouch, or template files were found.")
    elif verdict == VERDICT_MANUAL_CHECK_REQUIRED and not warnings and VERDICT_MANUAL_CHECK_REQUIRED not in classes:
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
        root / ".github" / "workflows",
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


def _gh_get_bytes(
    endpoint: str, accept: str, timeout: int, limit: int,
) -> Tuple[Optional[bytes], FetchStatus]:
    try:
        proc = subprocess.run(
            ["gh", "api", "-H", f"Accept: {accept}", endpoint],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "request timed out"
    except OSError:
        return None, "could not run gh"
    if proc.returncode != 0:
        error = re.search(rb"HTTP ([45][0-9]{2})\b", proc.stderr)
        return None, int(error.group(1)) if error else "gh API request failed"
    if len(proc.stdout) > limit:
        return None, f"response exceeds the {limit:,}-byte scan limit"
    return proc.stdout, 200


def _http_get_bytes_status(
    url: str, accept: str, timeout: int, limit: int,
) -> Tuple[Optional[bytes], FetchStatus]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None, resp.status
            raw = resp.read(limit + 1)
            if len(raw) > limit:
                return None, f"response exceeds the {limit:,}-byte scan limit"
            declared_length = resp.headers.get("Content-Length", "")
            if declared_length.isdecimal() and len(raw) != int(declared_length):
                return None, "truncated HTTP response"
            return raw, 200
    except urllib.error.HTTPError as exc:
        exc.close()
        return None, exc.code
    except (TimeoutError, urllib.error.URLError) as exc:
        if isinstance(exc, TimeoutError) or isinstance(exc.reason, TimeoutError):
            return None, "request timed out"
        return None, "HTTP request failed"
    except http.client.IncompleteRead:
        return None, "truncated HTTP response"
    except (OSError, http.client.HTTPException):
        return None, "HTTP request failed"


def _decode_api_json(raw: Optional[bytes], status: FetchStatus) -> Tuple[Optional[object], FetchStatus]:
    if raw is None:
        return None, status
    try:
        return json.loads(raw), 200
    except (ValueError, RecursionError):
        return None, "invalid JSON API response"


def _gh_api_json_status(endpoint: str, timeout: int = 15) -> Tuple[Optional[object], FetchStatus]:
    return _decode_api_json(*_gh_get_bytes(endpoint, "application/vnd.github+json", timeout, MAX_API_BYTES))


def _http_api_json_status(endpoint: str, timeout: int = 15) -> Tuple[Optional[object], FetchStatus]:
    url = f"https://api.github.com/{endpoint.lstrip('/')}"
    return _decode_api_json(*_http_get_bytes_status(url, "application/vnd.github+json", timeout, MAX_API_BYTES))


def _decode_policy_text(raw: Optional[bytes], status: FetchStatus) -> Tuple[Optional[str], FetchStatus]:
    if raw is None:
        return None, status
    try:
        return raw.decode("utf-8"), 200
    except UnicodeDecodeError:
        return None, "policy file is not valid UTF-8"


def _gh_fetch_raw(
    repo: str, branch: str, path: str, timeout: int = 15,
) -> Tuple[Optional[str], FetchStatus]:
    encoded_path = urllib.parse.quote(path, safe="/")
    ref = urllib.parse.quote(branch, safe="")
    endpoint = f"repos/{repo}/contents/{encoded_path}?ref={ref}"
    return _decode_policy_text(*_gh_get_bytes(endpoint, "application/vnd.github.raw+json", timeout, MAX_FILE_BYTES))


def _http_fetch_raw(
    repo: str, branch: str, path: str, timeout: int = 15,
) -> Tuple[Optional[str], FetchStatus]:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_branch = urllib.parse.quote(branch, safe="")
    url = f"https://raw.githubusercontent.com/{repo}/{encoded_branch}/{encoded_path}"
    return _decode_policy_text(*_http_get_bytes_status(url, "text/plain", timeout, MAX_FILE_BYTES))


def _fetch_error(status: FetchStatus) -> str:
    if status == 200:
        return "unexpected API response"
    return f"HTTP {status}" if isinstance(status, int) else status


def _list_remote_policy_paths(
    repo: str,
    branch: str,
    use_gh: bool,
    timeout: int,
) -> Tuple[Optional[List[str]], List[str]]:
    """List candidate paths and identify any listings that were incomplete."""
    api_status = _gh_api_json_status if use_gh else _http_api_json_status
    ref_q = urllib.parse.quote(branch, safe="")
    warnings: List[str] = []

    def _fetch_dir(directory: str) -> Tuple[Optional[List[object]], List[str]]:
        suffix = f"/{urllib.parse.quote(directory, safe='/')}" if directory else ""
        data, status = api_status(f"repos/{repo}/contents{suffix}?ref={ref_q}", timeout=timeout)
        location = f"{repo}@{branch}:{directory or '/'}"
        if not isinstance(data, list):
            return None, [f"Could not list {location} ({_fetch_error(status)})."]
        if len(data) >= CONTENTS_DIRECTORY_LIMIT:
            return data, [f"Listing {location} reached GitHub's {CONTENTS_DIRECTORY_LIMIT:,}-entry limit."]
        return data, []

    root_data, warnings = _fetch_dir("")
    if root_data is None:
        return None, warnings

    discovered: List[str] = []

    def _collect(entries: Sequence[object], directory: str) -> Dict[str, str]:
        subdirs: Dict[str, str] = {}
        invalid_entry = False
        for entry in entries:
            if not isinstance(entry, dict):
                invalid_entry = True
                continue
            entry_type = entry.get("type")
            path = entry.get("path")
            name = entry.get("name")
            if not all(isinstance(value, str) for value in (entry_type, path, name)):
                invalid_entry = True
                continue
            if entry_type == "dir":
                subdirs[name.lower()] = path
            elif _is_policy_path(path):
                if entry_type in {"file", "symlink"}:
                    discovered.append(path)
                else:
                    warnings.append(f"Could not read policy file {repo}@{branch}:{path} ({entry_type}).")
        if invalid_entry:
            warnings.append(f"Listing {repo}@{branch}:{directory or '/'} contained invalid entries.")
        return subdirs

    root_dirs = _collect(root_data, "")
    nested_plan = {
        ".github": ("issue_template", "pull_request_template", "workflows"),
        "docs": ("contributing",),
        "doc": ("contributing",),
    }
    level1_targets = (".github", "issue_template", "pull_request_template", "docs", "doc")
    level1_existing = [(key, root_dirs[key]) for key in level1_targets if key in root_dirs]
    level2_dirs: List[str] = []

    if level1_existing:
        with ThreadPoolExecutor(max_workers=min(6, len(level1_existing))) as pool:
            directories = [path for _, path in level1_existing]
            results = pool.map(_fetch_dir, directories)
            for (key, path), (entries, problems) in zip(level1_existing, results):
                warnings.extend(problems)
                if entries is not None:
                    child_dirs = _collect(entries, path)
                    level2_dirs.extend(child_dirs[child] for child in nested_plan.get(key, ()) if child in child_dirs)

    if level2_dirs:
        with ThreadPoolExecutor(max_workers=min(6, len(level2_dirs))) as pool:
            for path, (entries, problems) in zip(level2_dirs, pool.map(_fetch_dir, level2_dirs)):
                warnings.extend(problems)
                if entries is not None:
                    _collect(entries, path)

    return sorted(set(discovered)), warnings


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
    use_gh = source in {"auto", "gh"} and bool(shutil.which("gh"))
    if source == "gh" and not use_gh:
        return [], [f"Could not scan {repo}: requested 'gh' CLI was not found on PATH."]

    if not branch:
        api_status = _gh_api_json_status if use_gh else _http_api_json_status
        meta, status = api_status(f"repos/{repo}", timeout=timeout)
        if not isinstance(meta, dict) and status != 404 and source == "auto" and use_gh:
            # An unavailable or unauthenticated gh can be replaced by public HTTPS.
            use_gh = False
            meta, status = _http_api_json_status(f"repos/{repo}", timeout=timeout)
        if status == 404:
            return [], [] if optional_repo else [f"Repository {repo} was not found (HTTP 404)."]
        if isinstance(meta, dict) and isinstance(meta.get("default_branch"), str) and meta["default_branch"]:
            branch = meta["default_branch"]
        else:
            warnings.append(f"Could not look up the default branch for {repo} ({_fetch_error(status)}).")

    fetch_raw = _gh_fetch_raw if use_gh else _http_fetch_raw
    docs: List[ScannedFile] = []
    for candidate_branch in [branch] if branch else ["main", "master"]:
        paths, listing_warnings = _list_remote_policy_paths(repo, candidate_branch, use_gh, timeout)
        warnings.extend(listing_warnings)
        if paths is not None:
            if paths:
                with ThreadPoolExecutor(max_workers=min(8, len(paths))) as pool:
                    results = pool.map(lambda p: fetch_raw(repo, candidate_branch, p, timeout=timeout), paths)
                    for path, (content, status) in zip(paths, results):
                        if content is None:
                            warnings.append(
                                f"Could not read policy file {repo}@{candidate_branch}:{path} ({_fetch_error(status)})."
                            )
                        else:
                            docs.append(ScannedFile(f"{prefix}{path}", content, "gh" if use_gh else "raw"))
            return docs, warnings

        # A failed listing leaves custom filenames undiscovered. Probe known paths for restrictions.
        with ThreadPoolExecutor(max_workers=min(8, len(RAW_FALLBACK_PATHS))) as pool:
            results = pool.map(lambda p: _http_fetch_raw(repo, candidate_branch, p, timeout=timeout), RAW_FALLBACK_PATHS)
            for path, (content, status) in zip(RAW_FALLBACK_PATHS, results):
                if content is not None:
                    docs.append(ScannedFile(f"{prefix}{path}", content, "raw"))
                elif status != 404:
                    warnings.append(
                        f"Could not probe policy path {repo}@{candidate_branch}:{path} ({_fetch_error(status)})."
                    )
        if docs:
            warnings.append(
                f"Used direct raw-URL probes for {repo}@{candidate_branch}; custom policy paths may require manual review."
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
