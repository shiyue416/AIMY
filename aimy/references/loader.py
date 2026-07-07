"""ReferenceLoader — index and query 小十月 references (H1 reports, payloads,
playbooks, methodologies, dictionaries, templates).

Loads only on demand — doesn't dump 3,000+ files into every context.
Builds a keyword index at startup, returns top-N relevant files per task.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from dataclasses import dataclass, field

# ── Category definitions ────────────────────────────────────────────

REF_CATEGORIES = {
    "h1-reports": {
        "path": "references/h1-reports",
        "label": "H1 Reports",
        "trigger_keywords": [
            "h1", "report", "案例", "报告", "漏洞报告", "真实案例",
            "别人怎么挖", "参考案例", "类似漏洞",
        ],
        "phase": ["find", "prove", "report"],
        "priority": 8,
    },
    "playbooks": {
        "path": "references/playbooks",
        "label": "Playbooks",
        "trigger_keywords": [
            "playbook", "攻击流", "攻击链", "完整攻击", "剧本",
            "ssrf攻击", "xss利用", "rce链", "jwt攻击", "oauth",
            "saml", "lfi", "反序列化", "ssti", "xxe", "缓存",
            "内网", "提权", "横向", "上传绕过",
        ],
        "phase": ["find", "prove"],
        "priority": 9,
    },
    "payloader": {
        "path": "references/payloader",
        "label": "Payloads",
        "trigger_keywords": [
            "payload", "fuzz", "注入", "绕过", "bypass", "waf",
            "字典", "爆破", "wordlist", "编码",
        ],
        "phase": ["find", "prove"],
        "priority": 10,
    },
    "methodology": {
        "path": "references/methodology",
        "label": "Methodology",
        "trigger_keywords": [
            "methodology", "方法论", "优先级", "攻击优先",
            "绕过工具包", "证据", "控制缺口", "时间盒",
            "怎么挖", "策略",
        ],
        "phase": ["recon", "map", "find"],
        "priority": 7,
    },
    "dictionaries": {
        "path": "references/dictionaries",
        "label": "Dictionaries",
        "trigger_keywords": [
            "字典", "指纹", "默认口令", "默认密码", "src指纹",
            "中国", "国内", "cms识别",
        ],
        "phase": ["recon", "map", "find"],
        "priority": 6,
    },
    "templates": {
        "path": "references/templates",
        "label": "Templates",
        "trigger_keywords": [
            "template", "模板", "报告模板", "提交", "h1提交",
            "bugcrowd", "怎么写报告",
        ],
        "phase": ["report"],
        "priority": 5,
    },
}


@dataclass
class ReferenceEntry:
    """A single reference file."""
    path: str           # relative path from refs root
    abspath: str        # absolute path
    title: str          # first heading or filename
    category: str       # "h1-reports", "playbooks", etc.
    keywords: list[str] = field(default_factory=list)
    size_bytes: int = 0


class ReferenceLoader:
    """Loads and indexes reference files. Lazy content loading."""

    def __init__(self, refs_dir: str = ""):
        self.refs_dir = refs_dir
        self._entries: dict[str, ReferenceEntry] = {}
        self._indexed = False

    # ── Indexing ─────────────────────────────────────────────────

    def index(self) -> int:
        """Scan all reference directories and build keyword index. Returns count."""
        if self._indexed or not self.refs_dir:
            return len(self._entries)

        for cat_name, cat_cfg in REF_CATEGORIES.items():
            cat_path = os.path.join(self.refs_dir, cat_name)
            if not os.path.isdir(cat_path):
                continue
            self._index_category(cat_name, cat_path, cat_cfg)

        self._indexed = True
        return len(self._entries)

    def _index_category(self, cat_name: str, cat_path: str, cat_cfg: dict) -> None:
        """Walk a category directory and index all .md files."""
        for root, dirs, files in os.walk(cat_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fn in files:
                if not fn.endswith(".md") and not fn.endswith(".txt"):
                    continue
                abspath = os.path.join(root, fn)
                relpath = os.path.relpath(abspath, self.refs_dir)
                size = os.path.getsize(abspath)

                # Extract title from first line
                title = fn.replace(".md", "").replace(".txt", "").replace("-", " ")
                try:
                    with open(abspath, "r", encoding="utf-8", errors="replace") as f:
                        first_line = f.readline().strip().lstrip("#").strip()
                        if first_line:
                            title = first_line
                        # Read more for keywords
                        content_head = first_line + " " + f.read(500)
                except Exception:
                    content_head = title

                # Extract keywords from file name + content head
                keywords = self._extract_keywords(title, content_head, cat_cfg)

                entry = ReferenceEntry(
                    path=relpath,
                    abspath=abspath,
                    title=title,
                    category=cat_name,
                    keywords=keywords,
                    size_bytes=size,
                )
                self._entries[relpath] = entry

    def _extract_keywords(self, title: str, content: str, cat_cfg: dict) -> list[str]:
        """Extract meaningful keywords from title + leading content."""
        combined = (title + " " + content).lower()
        kw = set()

        # Security terms
        security_terms = [
            "xss", "ssrf", "sqli", "sql injection", "idor", "csrf", "xxe",
            "ssti", "rce", "lfi", "rfi", "command injection", "cmdi",
            "deserialization", "prototype pollution", "race condition",
            "open redirect", "path traversal", "file upload", "bypass",
            "authentication", "authorization", "access control",
            "ssrf", "cache", "host header", "http smuggling",
            "oauth", "saml", "jwt", "graphql", "api",
            "privilege escalation", "lateral movement", "credential",
            "prompt injection", "llm", "rag", "agent",
            "websocket", "csrf", "clickjacking", "cors",
            "business logic", "logic flaw", "payment",
            "supply chain", "dependency confusion",
            "cve", "exploit", "poc",
            "waf", "filter", "encoding", "double encoding",
            "unicode", "crlf", "null byte",
        ]
        for term in security_terms:
            if term in combined:
                kw.add(term)

        # Chinese security terms
        cn_terms = [
            "注入", "绕过", "攻击", "漏洞", "利用", "提权", "内网",
            "上传", "反序列化", "模板注入", "原型污染", "缓存",
            "提示注入", "越权", "未授权", "默认口令", "指纹",
        ]
        for term in cn_terms:
            if term in combined:
                kw.add(term)

        # Add category trigger keywords that match
        for tkw in cat_cfg.get("trigger_keywords", []):
            if tkw.lower() in combined:
                kw.add(tkw.lower())

        return sorted(kw)

    # ── Query ────────────────────────────────────────────────────

    def find_relevant(self, task: str = "", phase: str = "",
                      vuln_class: str = "", max_results: int = 10) -> list[ReferenceEntry]:
        """Find top-N reference files relevant to a task/phase/vuln_class."""
        if not self._indexed:
            self.index()

        task_lower = task.lower()
        results: list[tuple[int, ReferenceEntry]] = []

        for entry in self._entries.values():
            score = 0

            # Phase match
            cat_cfg = REF_CATEGORIES.get(entry.category, {})
            if phase and phase in cat_cfg.get("phase", []):
                score += 5

            # Keyword match in title
            title_lower = entry.title.lower()
            for word in task_lower.split():
                if len(word) > 2 and word in title_lower:
                    score += 3

            # Keyword match in entry keywords
            for kw in entry.keywords:
                if kw in task_lower:
                    score += 4
                if vuln_class and kw == vuln_class.lower():
                    score += 10

            # Category trigger match
            for tkw in cat_cfg.get("trigger_keywords", []):
                if tkw in task_lower:
                    score += 2

            # Priority boost
            score += cat_cfg.get("priority", 5)

            if score > 0:
                results.append((score, entry))

        results.sort(key=lambda x: -x[0])
        return [e for _, e in results[:max_results]]

    def search(self, query: str, max_results: int = 10) -> list[ReferenceEntry]:
        """Free-text search across all reference titles and keywords."""
        if not self._indexed:
            self.index()

        q = query.lower()
        results: list[tuple[int, ReferenceEntry]] = []

        for entry in self._entries.values():
            score = 0
            title_lower = entry.title.lower()

            # Title match
            for word in q.split():
                if len(word) > 1 and word in title_lower:
                    score += 5

            # Keyword match
            for kw in entry.keywords:
                if kw in q:
                    score += 3

            # Content match (lightweight — just the stored keywords)
            if q in " ".join(entry.keywords):
                score += 2

            if score > 0:
                results.append((score, entry))

        results.sort(key=lambda x: -x[0])
        return [e for _, e in results[:max_results]]

    def load_content(self, entry: ReferenceEntry, max_chars: int = 4000) -> str:
        """Load the actual content of a reference file, truncated."""
        try:
            with open(entry.abspath, "r", encoding="utf-8", errors="replace") as f:
                text = f.read(max_chars)
            if len(text) >= max_chars:
                text += "\n\n... [truncated]"
            return text
        except Exception:
            return f"[Error reading {entry.path}]"

    def get_by_path(self, relpath: str) -> ReferenceEntry | None:
        """Get a specific reference entry by relative path."""
        if not self._indexed:
            self.index()
        return self._entries.get(relpath)

    @property
    def total(self) -> int:
        if not self._indexed:
            self.index()
        return len(self._entries)

    @property
    def categories(self) -> dict[str, int]:
        if not self._indexed:
            self.index()
        counts: dict[str, int] = {}
        for e in self._entries.values():
            counts[e.category] = counts.get(e.category, 0) + 1
        return counts

    @property
    def is_indexed(self) -> bool:
        return self._indexed
