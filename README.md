# fusion-router — 四源统一安全技能调度中枢

> 一个文件调度 940+ 安全技能 + 71 自动渗透工具 + 52MB 漏洞资源

## 一句话

**HackSkills = 攻击 · Anthropic = 防御 · src-hunter = 深度 · Python = 执行**

## 覆盖

| 源 | 技能数 | 视角 | 位置 |
|----|--------|------|------|
| HackSkills (四月) | 101 技能 + 71 Python 工具 | 攻击/利用 | `../四月-skill-main/` |
| Anthropic Cybersecurity | 817 技能 | 防御/取证/合规 | `../Anthropic-Cybersecurity-Skills-1.3.0/` |
| src-hunter | 52MB 深度资源 | 方法论/Payload | `.claude/skills/src-hunter/` |
| 洺熙注入层 | 5 配置 + Hook | 上下文注入 | `../安全研究上下文注入/` |

## 使用

```
Skill("fusion-router")
```

或者直接读取：`Read fusion-router/SKILL.md`

## 速查

| 用户说 | 加载 |
|--------|------|
| "挖洞/SRC" | `hack` → 具体漏洞skill + Python 工具 |
| "取证/恶意软件/威胁情报/SOC" | Anthropic 对应域 |
| "报告/H1案例" | `report-writing` + `src-hunter` |
| "供应链安全" | HackSkills + Anthropic 双方 |
| "CTF" | HackSkills + Python `solve_full.py` |

## 文件

- `SKILL.md` — 主路由文件 (542行)
- `FUSION_ROUTES.md` — 漏洞→技能精确映射
- `INDEX.md` — 完整技能索引
- `references/` — 本地引用资源目录
- `skills/` — 本地技能目录 (可放置自定义技能)
- `tools/` — 本地工具目录 (可放置自写脚本)
