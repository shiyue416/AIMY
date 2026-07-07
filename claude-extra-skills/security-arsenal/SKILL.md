---
name: security-arsenal
description: Quick-reference methodology cheatsheet for the bug bounty hunt — per-vuln punchlists (IDOR/XSS/SSRF/SQLi/Upload/...), tool command snippets, payload templates. A fast lookup companion to the authoritative deep skills. Use when deep skills are loaded and you need a rapid checklist, or when scanning through many endpoints looking for low-hanging fruit. Not a standalone methodology — always load the authoritative deep skill first per FUSION_ROUTES.md.
---

# Security Arsenal — Quick-Reference Cheatsheet

> **定位**: 速查表，不是独立方法论。
> **使用方式**: 先通过 `FUSION_ROUTES.md` 加载权威 Skill，再用本表做快速 check。
> **完整内容**: 见 `METHODOLOGY_CHEATSHEET.md` (漏洞速查) + `REFERENCES.md` (上游项目链接)

---

## 快速导航

| 文件 | 内容 |
|------|------|
| [METHODOLOGY_CHEATSHEET.md](METHODOLOGY_CHEATSHEET.md) | IDOR/XSS/SSRF/SQLi/Upload/... 每个漏洞类的快速检查清单 |
| [REFERENCES.md](REFERENCES.md) | 上游 Bug Bounty 知识库链接 (HowToHunt/HolyTips/AllAboutBugBounty) |

---

## 使用协议

1. **先加载权威 Skill** — 查 `FUSION_ROUTES.md` 找到当前漏洞类的 ★ 权威 Skill
2. **再打开本表** — 作为快速检查清单，避免遗漏明显问题
3. **不要跳过深度** — 本表覆盖的是"快速扫"层面，深度利用仍需权威 Skill

---

## 典型工作流

```
/start target.com
  → bb-methodology (Phase 3: Hunt)
    → /hunt --vuln-class idor
      → ★ idor-broken-object-authorization (深度)
      → ☆ security-arsenal (速查: 6 种 IDOR 变体)
      → ☆ web2-vuln-classes §IDOR (工具链)
```

---

> 本 Skill 由融合系统修复 (原安装损坏，缺 SKILL.md)。2026-06-17.
