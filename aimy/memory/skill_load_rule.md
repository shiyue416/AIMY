---
name: skill-load-rule
description: 挖洞前必须先确认加载了正确的技能文件
metadata:
  type: feedback
  source: user
---

每次挖洞前:
1. 根据目标URL/参数/功能判断需要的技能类型
2. Read 对应的 SKILL.md 文件
3. 确认给用户后，再动手测试

不凭记忆输出payload，不跳过技能文件读取。

触发词→技能映射表见 C:\Users\PC\.claude\CLAUDE.md 的"自动技能加载规则"章节。
