---
name: file-access-vuln
description: >-
  Entry P1 category router for file access and upload workflows. Use when
  testing download endpoints, file paths, local file inclusion, upload flows,
  preview pipelines, archive extraction, or storage and sharing boundaries.
---

# File Access Router

This is the routing entry point for filesystem paths, download endpoints, upload pipelines, and file preview handling.

## When to Use

- Parameters, filenames, download endpoints, or import flows influence file paths
- The target supports upload, preview, transcoding, extraction, sharing, download, or proxied file access
- You need to decide whether this is path traversal/LFI or an upload-validation/processing-chain issue

## Skill Map

- [Path Traversal LFI](../path-traversal-lfi/SKILL.md): path traversal, file read, wrapper abuse, include chains
- [Upload Insecure Files](../upload-insecure-files/SKILL.md): upload validation, storage paths, processing chains, overwrite risk, preview/share boundaries

## Recommended Flow

1. First identify whether the entry point is a path parameter, download endpoint, or upload workflow
2. Then locate whether the issue appears in accept, store, process, or serve stages
3. Small path-chain and upload-bypass samples are merged into the main topic skills; no separate payload entry is needed

## Related Categories

- [injection-checking](../injection-checking/SKILL.md)
- [business-logic-vuln](../business-logic-vuln/SKILL.md)

<!-- FLYWHEEL_APPEND -->
<!-- 以下内容由 EVX 飞轮自动维护，手动编辑会被覆盖 -->

## 🔄 飞轮进化技法 (auto-updated 2026-07-07 17:08)

> 以下技法是该漏洞类型中**H1 真实 accept 记录里综合得分最高的一项**。
> 遇到此类漏洞时**优先尝试此技法**。

### 🏆 remote file inclusion

| 指标 | 值 |
|------|----|
| 接受率 | **75%** (3/4) |
| 平均赏金 | ¥1 |
| 漏洞类型 | `remote file inclusion` |

