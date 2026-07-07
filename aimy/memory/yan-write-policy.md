---
name: yan-write-policy
description: 所有记录写入彦目录，不写入 .claude
metadata: 
  node_type: memory
  type: feedback
  source: user
  originSessionId: 25f92610-30bb-46ac-9afd-0dbb369bfbab
---

所有飞轮记录、technique 入库、配置变更、技能升级等操作，一律写入 `C:\Users\PC\Desktop\彦/` 目录，不写入 `.claude/` 目录。

**Why:** 用户将彦作为所有安全工作的统一工作台和持久化存储，.claude/ 是 Claude Code 的临时配置目录。

**How to apply:**
- techniques → `彦/aimy/memory/techniques.jsonl`
- session_brief → `彦/aimy/session_brief.md`
- 技能升级 → `彦/skills/<name>/SKILL.md`
- 配置文件 → `彦/aimy/` 下对应模块
- `.claude/targets/techniques.jsonl` 不同步写入
- 除非文件明确在 `.claude/` 路径下（如 `CLAUDE.md`），否则不走 `.claude/`
