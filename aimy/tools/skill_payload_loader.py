"""
Skill Payload Loader — 从 Skill MD 文件中提取 payload 和技法。

quickhunt 在跑检测器之前先调这个，
用 Skill 里的真实 payload 替代检测器硬编码的通用 payload。
"""

import re, os
from pathlib import Path
from typing import Optional, Dict, List

SKILLS_DIR = Path(r"C:\Users\PC\Desktop\彦\skills")

# vuln_type → Skill directory name
VULN_TO_SKILL = {
    "xss": "xss-cross-site-scripting",
    "sqli": "sqli-sql-injection",
    "cmdi": "cmdi-command-injection",
    "ssti": "ssti-server-side-template-injection",
    "ssrf": "ssrf-server-side-request-forgery",
    "idor": "idor-broken-object-authorization",
    "auth_bypass": "authbypass-authentication-flaws",
    "lfi": "path-traversal-lfi",
    "path_traversal": "path-traversal-lfi",
    "jwt": "jwt-oauth-token-attacks",
    "deserialization": "deserialization-insecure",
    "nosqli": "nosql-injection",
    "graphql": "graphql-audit",
    "xxe": "xxe-xml-external-entity",
    "race_condition": "race-condition",
    "file_upload": "upload-insecure-files",
    "open_redirect": "open-redirect",
    "csrf": "csrf-cross-site-request-forgery",
    "cors": "cors-cross-origin-misconfiguration",
    "proto_pollution": "prototype-pollution",
    "request_smuggling": "request-smuggling",
    "business_logic": "business-logic-vulnerabilities",
}


def _extract_code_blocks(content: str, lang_filter: Optional[str] = None) -> List[str]:
    """Extract code blocks from markdown. Optionally filter by language tag."""
    blocks = []
    pattern = re.compile(r'```(\w*)\n(.*?)```', re.DOTALL)
    for match in pattern.finditer(content):
        lang = match.group(1).strip().lower()
        code = match.group(2).strip()
        if lang_filter and lang != lang_filter:
            continue
        blocks.append(code)
    return blocks


def _extract_table_rows(content: str, section_header: str) -> List[Dict]:
    """Extract rows from a markdown table after a section header."""
    # Find section
    lines = content.split("\n")
    in_section = False
    in_table = False
    headers = []
    rows = []

    for line in lines:
        if section_header.lower() in line.lower() and line.strip().startswith("#"):
            in_section = True
            continue
        if in_section and line.strip().startswith("#") and not line.strip().startswith("##"):
            break  # next top-level section

        if in_section:
            if "|" in line and not in_table:
                in_table = True
                headers = [h.strip().lower() for h in line.split("|") if h.strip()]
                continue
            if in_table and re.match(r'^\|[\s\-:|]+\|$', line):
                continue  # separator row
            if in_table and "|" in line:
                cells = [c.strip() for c in line.split("|") if c.strip()]
                if len(cells) == len(headers):
                    rows.append(dict(zip(headers, cells)))
            elif in_table:
                in_table = False

    return rows


def _extract_bullet_payloads(content: str) -> List[str]:
    """Extract payloads from bullet lists (common in Skill files)."""
    payloads = []
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped.startswith("- ") and ("`" in stripped):
            # Extract backtick-quoted payloads
            for m in re.finditer(r'`([^`]+)`', stripped):
                payload = m.group(1)
                if len(payload) > 2 and len(payload) < 500:
                    payloads.append(payload)
    return payloads


def load_skill_payloads(vuln_type: str) -> List[str]:
    """Load all payloads for a vulnerability type from its Skill file."""
    skill_name = VULN_TO_SKILL.get(vuln_type)
    if not skill_name:
        return []

    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    if not skill_path.exists():
        return []

    content = skill_path.read_text(encoding="utf-8", errors="ignore")
    payloads = []

    # 1. Code blocks
    for lang in ["html", "javascript", "sql", "python", "bash", "text", ""]:
        for block in _extract_code_blocks(content, lang):
            for line in block.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("//"):
                    if len(line) > 3 and len(line) < 500:
                        payloads.append(line)

    # 2. Inline code in tables and lists
    for m in re.finditer(r'`([^`]{3,200})`', content):
        payloads.append(m.group(1))

    # 3. HTTP request examples
    for m in re.finditer(r'(GET|POST)\s+(/\S+)', content):
        payloads.append(m.group(2))

    # Deduplicate, remove noise
    seen = set()
    filtered = []
    noise = {"x", "y", "z", "a", "b", "c", "id", "name", "input", "INPUT",
             "page", "url", "token", "test", "null", "true", "false",
             "alert(1)", "alert('XSS')"}
    for p in payloads:
        p = p.strip().strip('"').strip("'")
        if p.lower() in noise or len(p) < 3:
            continue
        if p not in seen:
            seen.add(p)
            filtered.append(p)

    return filtered[:50]  # Cap at 50 payloads


def load_skill_techniques(vuln_type: str) -> List[str]:
    """Extract technique descriptions from Skill file (WAF bypass, etc)."""
    skill_name = VULN_TO_SKILL.get(vuln_type)
    if not skill_name:
        return []

    skill_path = SKILLS_DIR / skill_name / "SKILL.md"
    if not skill_path.exists():
        return []

    content = skill_path.read_text(encoding="utf-8", errors="ignore")
    techniques = []

    # Extract lines with technique descriptions
    for line in content.split("\n"):
        line = line.strip()
        # Look for technique indicators
        if any(kw in line.lower() for kw in [
            "bypass", "bypasses", "if blocked", "if filtered",
            "when waf", "alternative", "try instead", "trick",
            "evasion", "smuggl", "obfuscat"
        ]):
            if len(line) > 20:
                techniques.append(line[:200])

    return techniques[:20]


def get_skill_payload_context(vuln_type: str) -> Dict:
    """Get complete payload + technique context for a vulnerability type."""
    return {
        "vuln_type": vuln_type,
        "skill_name": VULN_TO_SKILL.get(vuln_type),
        "payloads": load_skill_payloads(vuln_type),
        "techniques": load_skill_techniques(vuln_type),
    }
