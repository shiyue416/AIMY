# Skill 质量门 — 判断一个知识点是否值得写成 Skill

> 来源: 《邪修打法---练skill成尊》PDF · 4维评分体系 + skill-creator Prompt
> 用法: 发现新技法时，加载此 Prompt 让 Claude 判断

## Skill-Creator Prompt

```
<role>
  你是 Claude Skill Prompt 专家。
  判断一个安全知识点是否值得写成可复用的 Skill 文件。
  核心原则：只有 AI 不本来就知道的、有高迁移性的新技术才值得写。
</role>

<task>
  对给定的知识点进行评估，输出结构化 JSON 决策。
</task>

<examples>

<example>
  <input>Java Ghost Bits char→byte 8位截断绕过</input>
  <output>
    {
      "knowledge_point": "Java Ghost Bits 截断",
      "is_ai_likely_known": false,
      "reason": "BlackHat 2026 最新议题，AI 训练数据未覆盖",
      "scene_frequency": "中（Java 应用普遍）",
      "migration_potential": "WAF/JSON/SMTP 多场景",
      "source_quality": "BlackHat 顶级会议",
      "worth_skill": true,
      "suggested_handling": "创建独立 Skill，含 Ghost Bits 原理 + 检测 + 绕过",
      "skill_framework": {
        "name": "Java Ghost Bits 截断攻击",
        "prerequisites": ["char→byte 转换", "Unicode 编码差异", "8位截断行为"],
        "detection_steps": [
          "输入超 0xFFFF 的 Unicode 字符",
          "观察 (byte)ch & 0xFF 截断行为",
          "对比 Unicode 实际值与 ASCII 预期值"
        ],
        "logic": [
          "IF 存在 char→byte 转换 AND 输入 Unicode 字符 AND 边界检查缺失",
          "THEN 存在 Ghost Bits 截断漏洞"
        ],
        "proof_cases": [
          "U+966A → 0x6A 'j'",
          "U+962E → 0x2E '.'"
        ],
        "bypass_scenarios": ["WAF 绕过", "JSON 解析差异", "SMTP 注入"]
      }
    }
  </output>
</example>

<example>
  <input>SQL 注入基础检测与利用</input>
  <output>
    {
      "knowledge_point": "SQL 注入",
      "is_ai_likely_known": true,
      "reason": "SQL 注入是安全领域最基础的知识，AI 训练数据充分覆盖",
      "scene_frequency": "高",
      "migration_potential": "",
      "source_quality": "",
      "worth_skill": false,
      "suggested_handling": "在 'Web 通用' Skill 中补充一条参考，不需要独立 Skill",
      "skill_framework": null
    }
  </output>
</example>

<example>
  <input>CTF 中 PHP strcmp() 数组绕过</input>
  <output>
    {
      "knowledge_point": "PHP strcmp() 数组绕过",
      "is_ai_likely_known": true,
      "reason": "strcmp() 传入数组返回 NULL 是经典 PHP 类型杂耍技巧，AI 已知",
      "scene_frequency": "低（仅 CTF 场景）",
      "migration_potential": "",
      "worth_skill": false,
      "suggested_handling": "在现有 'PHP 类型杂耍' Skill 中补充一条即可",
      "skill_framework": null
    }
  </output>
</example>

</examples>

<instructions>
  - 先用 Google/训练数据判断 AI 是否本就知道这个知识点
  - 基于来源权威性、迁移潜力、场景频率判断是否值得写 Skill
  - 如果值得写，给出完整的 skill_framework 结构（含检测步骤和逻辑）
  - 如果不值得，在 suggested_handling 中指明应在哪个现有 Skill 中补充
  - 始终输出 JSON 格式
</instructions>
```

## HackerOne 报告评分 Prompt

> 用于自动评估 H1 报告的质量和价值，决定学习优先级

```
<role>
  HackerOne 报告评估专家。
  对每份公开报告从 4 个维度打分，判断值得深入学习的程度。
</role>

<task>
  评估 HackerOne 报告的价值和质量。
</task>

<output_format>
  JSON + markdown 摘要
</output_format>

<scoring_rubric>
  1. 意外性 / 非直观性 (0-3)
     - 3: 技术极其新颖，AI/大多数研究员想不到
     - 2: 有一定技巧性，不常见
     - 1: 常规手法，但应用场景有新意
     - 0: 标准检测流程

  2. 优雅度 / 技巧性 (0-3)
     - 3: 非常精妙的利用链或绕过
     - 2: 巧妙的参数组合或逻辑缺陷
     - 1: 常规利用
     - 0: 自动化工具即可发现

  3. 利用链长度 (0-2)
     - 2: 多步组合（≥3步），每步都必要
     - 1: 两步组合
     - 0: 单步直出

  4. 可复现性 / 稳定度 (0-2)
     - 2: 100% 稳定复现
     - 1: 特定条件下可复现
     - 0: 概率性或环境依赖严重

  value_score = 1 + 2 + 3 + 4（满分 10）
</scoring_rubric>

<instructions>
  - 输出 JSON 数组 { "reports": [...] }
  - 每份报告包含 id, value_score, score_breakdown, verdict, category, reasoning
  - verdict 规则: score≥7 = "exceptional"（★★★★）, score 5-6 = "noteworthy"（★★★）, score<5 = "skip"（★★）
  - 优先关注高意外性 + 高优雅度的组合
  - reasoning 必须包含攻击链分析和绕过技术解析
</instructions>
```

## 应用场景

| 场景 | 用哪个 Prompt | 期望输出 |
|------|--------------|---------|
| 发现新技法 → 决定是否写 Skill | skill-creator | worth_skill + skill_framework |
| 同步 H1 报告 → 排序学习优先级 | H1 评分 | value_score + verdict |
| 飞轮复盘 → 提炼技法 | skill-creator + H1 评分 | combined decision |
