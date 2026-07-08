# AIMY v3.0 — AI Bug Bounty Hunting Framework

<p align="center">
  <strong>180+ attack skills &middot; 120+ Python detectors &middot; 3,000+ H1 reports &middot; 50,000 WooYun cases</strong><br>
  Four-source fusion — HackSkills · Anthropic · src-hunter · Mingxi injection<br>
  <sub>7-phase hunt pipeline · 35 trigger-keyword auto-load · 14-project red-line comparison (45/50)</sub>
</p>

---

## Quick Start

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
cp .env.example .env          # fill in your API keys (see Configuration below)
pip install -r aimy/requirements.txt

# Start hunting
python aimy.py                              # interactive mode
python aimy.py --target example.com         # targeted hunt
python aimy.py -q "hunt example.com"        # single query
```

---

## 使用指南 — 新用户从零开始

### 第一步：安装

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
pip install -r aimy/requirements.txt
```

### 第二步：配置

```bash
cp .env.example .env
```

编辑 `.env`，至少填入：

```ini
GPT5_API_KEY=sk-你的APIKey   # 必填 — LLM 提供商
```

可选项：

```ini
AIMY_MODE=veteran               # veteran（默认，只关注高价值漏洞）| rookie（完整输出）
AIMY_SCENE=bounty               # bounty（默认）| pentest | redteam | auto-pentest
H1_USERNAME=你的H1用户名        # HackerOne 飞轮同步
H1_TOKEN=你的H1_Token           # HackerOne 飞轮同步
BURP_MCP_TOKEN=你的BurpToken    # Burp Suite 集成
```

### 第三步：验证环境

```bash
python aimy.py --list-providers     # 确认 LLM 连通
python -m aimy.memory.session_brief # 查看本周高命中技法排行（可选）
```

### 第四步：开始挖洞

```bash
# 交互模式 — 直接敲命令
python aimy.py

# 一句话模式 — 单次查询
python aimy.py -q "hunt example.com 挖 ssrf"

# 目标模式 — 对单个域名跑完整流程
python aimy.py --target example.com
```

### 第五步：走七阶段管线

```bash
/recon target.com              # Phase 2 — 被动侦察（零发包）
/hunt target.com               # Phase 3+4 — 主动探测 + 漏洞挖掘
/hunt target.com --vuln-class sqli   # Phase 4 — 只挖 SQL 注入
/hunt target.com --autonomous        # Phase 4 — 全覆盖（26 类漏洞，每类 ≥25 次）
/validate                      # Phase 5 — 8 问验证门
/report                        # Phase 6 — 生成可提交的报告
/report bounty                 # Phase 6 — 赏金平台格式（H1/Bugcrowd/Intigriti）
```

### 第六步：看懂输出

| 输出 | 含义 |
|------|------|
| `[vuln] Confirmed: SSRF in /api/proxy` | 已验证的漏洞 — 可以写报告 |
| `[warn] Downgraded: reflected XSS → informatory` | 确认存在但影响低 — 跳过（老鸟模式自动过滤） |
| `[reject] Rejected by Validator (Q3: 不在 scope)` | 未通过验证门 — 不要提交 |
| `No signal on /api/...` | 端点测过了，没东西 — 换下一个 |

### 第七步：迭代进化

```bash
# 跑飞轮 — 从你的发现中自动学习
python aimy.py --flywheel

# 查看更新的技法排名
python -m aimy.memory.session_brief

# 带着更新的知识挖下一个目标
python aimy.py --target 下一个目标.com
```

---

## 运行模式

两种运行时模式 + 四种场景模式，通过环境变量控制。

### 老鸟 vs 菜鸟

| 模式 | 环境变量 | 行为 |
|------|---------|------|
| **老鸟**（默认） | `AIMY_MODE=veteran` | 只关注高价值漏洞。自动过滤 `reflected_xss \| open_redirect \| info_disclosure \| low \| info \| information`。输出简洁。 |
| **菜鸟** | `AIMY_MODE=rookie` | 完整输出 + 修复建议。不按严重程度过滤。 |

### 场景模式

| 场景 | `AIMY_SCENE=` | 目标 | 关键区别 |
|------|--------------|------|----------|
| **赏金**（默认） | `bounty` | 找 SRC/H1 高赏金漏洞 | 只读，证明即停，最多取 3 条用户数据 |
| **渗透测试** | `pentest` | 完整渗透交付报告 | 后利用链、横向移动、证据收集 |
| **红队** | `redteam` | 模拟真实攻击 | 杀伤链导向、隐蔽、持久化评估 |
| **全自动渗透** | `auto-pentest` | 端到端自主渗透 | 无人介入，全量覆盖 |

```bash
# 示例：菜鸟模式 + 赏金场景
AIMY_MODE=rookie AIMY_SCENE=bounty python aimy.py --target target.com

# 示例：老鸟模式 + 全自动渗透
AIMY_MODE=veteran AIMY_SCENE=auto-pentest python aimy.py --target target.com --autonomous
```

---

## Architecture

```
aimy/                          Python framework
├── core/                      Orchestrator, ReAct loop, state machine, bus
├── tools/                     120+ vulnerability detectors (BaseDetector template)
│   ├── ssrf_detector.py       SSRF with OOB/interactsh integration
│   ├── sqli_blind.py          Boolean/time-based blind SQLi
│   ├── xss_detector.py        Reflected/Stored/DOM XSS with browser verification
│   ├── ssti_detector.py       SSTI with 20+ template engines
│   ├── jwt_detector.py        JWT alg:none, weak secret, kid injection
│   ├── race_condition.py      TOCTOU with parallel request engine
│   ├── deser_weaponizer.py    Java/Python/PHP deserialization gadget chains
│   └── ...                    115+ more detectors
├── memory/                    Flywheel: FeedbackDB, EVX evolution engine, session_brief
├── llm/                       Multi-provider LLM client (GPT-5.5, LongCat, Claude)
├── safety/                    Safety gate, scope validator, audit trail
├── skills/                    Skill loader, registry, router, formatter
├── references/                Reference loader (keyword-indexed, on-demand)
└── telemetry/                 (Removed — merged into memory/flywheel.py)

skills/                        180 attack methodology skills
├── ssrf-server-side-request-forgery/    SKILL.md + SCENARIOS.md + BYPASS.md
├── sqli-sql-injection/                  SKILL.md + BLIND.md + OOB.md + UNION.md
├── xss-cross-site-scripting/            SKILL.md + DOM.md + CSP_BYPASS.md
└── ...                                  176 more skill directories

anthropic-skills/              8,946 defense/forensics/compliance skills
references/                    5,891 reference files
├── hackerone-reports/          3,029 disclosed H1 reports (indexed by vuln class)
├── payload-kit/                52 specialized payload collections
├── playbooks/                  68 attack playbooks
└── nuclei-templates-ai/        Auto-generated Nuclei templates
```

---

## 使用 — 七阶段挖洞管线

每次挖洞遵循确定性七阶段流程，每阶段有入口/出口关卡。

### Phase 1: Intake (5 min)

Scope validation, rule loading, timebox setting.

```bash
# AI-driven intake
/recon target.com          # triggers Phase 1→2

# Manual scope check
python aimy.py --target target.com --scope-only
```

### Phase 2: Recon — 6-Dimension Passive

**Zero packets sent to target.** All data from third-party sources.

| Dimension | Source | Coverage |
|-----------|--------|----------|
| 1. Subdomain passive | crt.sh, Chaos, subfinder, amass (-passive) | 85-92% |
| 2. Permutation mutation | dnsgen (suffix), alterx (NLP word-segment) | 1→50x multiplier |
| 3. Favicon correlation | mmh3 hash → FOFA icon_hash / Shodan http.favicon | Cross-asset discovery |
| 4. ASN/IP reverse | asnmap, amass intel, bgp.he.net, RADB whois | Network-level correlation |
| 5. CSP intelligence | CSP header parsing → trusted domain list → httpx liveness | Free subdomains |
| 6. JS sourcemap | .js.map → source-map-unpack → TS source → endpoints + creds | Source-level attack surface |

```bash
/recon target.com                           # all 6 dimensions
/favicon-hunt --url https://target.com      # dimension 3 only
/asn-discovery --org "Target Corp"          # dimension 4 only
/csp-intel --url https://target.com         # dimension 5 only
/js-sourcemap --recon-dir recon/target.com  # dimension 6 only
```

### Phase 3: Enum — Active Probing

Rate-limited active enumeration with safety pre-checks.

```bash
/hunt target.com              # triggers Phase 3→4
/hunt target.com --vuln-class ssrf   # focus on one class
```

### Phase 4: Hunt — Signal→Playbook→Tool Dispatch

Three-level dispatch engine:

1. **Signal detection** — parameter names, HTTP headers, response patterns
2. **Playbook selection** — maps signal to specific skill+tool
3. **Tool execution** — runs the Python detector with the right payload

```bash
# Targeted hunting
/hunt target.com --vuln-class idor
/hunt target.com --vuln-class sqli
/hunt target.com --vuln-class ssti

# Autonomous (exhaustive — 26 vuln classes, ≥25 attempts/class, ≥90 min)
/hunt target.com --autonomous
```

### Phase 5: Validate — 8-Question Gate + 4 Acceptance Gates

Every finding must pass:

| Q# | Question | Fail = |
|----|----------|--------|
| Q1 | Is there actual impact? | Reject |
| Q2 | Is the impact type in the program's accepted list? | Reject |
| Q3 | Is the root cause on an in-scope asset? | Reject |
| Q4 | Can it be reproduced consistently? | Reject |
| Q5 | Is there a more severe exploitation path? | Upgrade |
| Q6 | Are all PII redacted in evidence? | Fix |
| Q7 | Does it violate any red-line rule? | Reject |
| Q8 | Is this a duplicate? | Dedup |

4 Acceptance Gates: evidence completeness, impact authenticity, compliance, anonymization.

```bash
/validate           # runs the 8-question gate
```

### Phase 6: Report — Template-Driven

Generates submission-ready reports with:
- Vulnerability overview
- Technical analysis (root cause, trigger condition, attack surface)
- Reproduction steps / PoC
- Impact assessment
- Remediation suggestions

```bash
/report             # generate report for all confirmed findings
/report bounty      # bounty-platform format (H1/Bugcrowd/Intigriti)
/report pentest     # pentest deliverable format
```

### Phase 7: Flywheel — Auto-Evolution

Records technique outcomes, triggers skill upgrades, refreshes session brief.

```bash
# Manual flywheel run
python -m aimy.memory.flywheel

# Read this week's top techniques
python -m aimy.memory.session_brief
```

---

## Skill 自动加载系统

每种漏洞类都有触发词表。当 AI 在用户输入或目标响应中检测到匹配关键词时，对应 Skill 在**生成任何 payload 之前**自动加载。

**硬约束：禁止凭记忆生成 payload — 一切来自 Skill 文件。**

| Trigger Keywords | Skill Loaded |
|-----------------|-------------|
| SSRF / url= / webhook / proxy / fetch / callback | `ssrf-server-side-request-forgery/SKILL.md` |
| SQLi / id= / 注入 / union / select / sleep / error | `sqli-sql-injection/SKILL.md` |
| XSS / q= / search / innerHTML / DOM / 跨站 / alert | `xss-cross-site-scripting/SKILL.md` |
| IDOR / /api/user/ / 越权 / uuid / BOLA | `idor-broken-object-authorization/SKILL.md` |
| CMDi / cmd= / exec / shell / ping / command | `cmdi-command-injection/SKILL.md` |
| SSTI / template / {{ / {% / render / jinja / twig | `ssti-server-side-template-injection/SKILL.md` |
| JWT / Bearer / eyJ / token / alg / kid | `jwt-oauth-token-attacks/SKILL.md` |
| Auth / 登录 / bypass / 绕过 / OAuth / SSO | `authbypass-authentication-flaws/SKILL.md` |
| LFI / file= / path= / ../ / 目录遍历 / 文件包含 | `path-traversal-lfi/SKILL.md` |
| XXE / xml / <!DOCTYPE / upload .xml / svg | `xxe-xml-external-entity/SKILL.md` |
| CSRF / 跨站请求 / form / action= | `csrf-cross-site-request-forgery/SKILL.md` |
| Upload / 文件上传 / multipart / avatar | `upload-insecure-files/SKILL.md` |
| Deser / 反序列化 / serialize / pickle / ObjectInputStream | `deserialization-insecure/SKILL.md` |
| Race / 竞态 / TOCTOU / race condition | `race-condition/SKILL.md` |
| CORS / Access-Control / 跨域 / preflight | `cors-cross-origin-misconfiguration/SKILL.md` |
| GraphQL / graphql / introspection | `graphql-audit/SKILL.md` |
| HTTP Smuggling / CL.TE / TE.CL / desync | `request-smuggling/SKILL.md` |
| Cache / CDN / cache poisoning | `web-cache-deception/SKILL.md` |
| Prototype Pollution / __proto__ / constructor | `prototype-pollution/SKILL.md` |
| 403 / 401 / forbidden / access denied | `401-403-bypass-techniques/SKILL.md` |
| Business Logic / 支付 / 订单 / coupon / biz | `business-logic-vulnerabilities/SKILL.md` |
| LLM / AI / prompt injection / chatbot | `llm-prompt-injection/SKILL.md` |
| WAF / cloudflare / akamai / blocked | `waf-bypass-techniques/SKILL.md` |
| Host header / X-Forwarded-Host / password reset poison | `http-host-header-attacks/SKILL.md` |
| .git / .env / backup / DS_Store / 源码泄露 | `insecure-source-code-management/SKILL.md` |
| Subdomain Takeover / CNAME / 接管 | `subdomain-takeover/SKILL.md` |
| Open Redirect / redirect= / next= / 跳转 | `open-redirect/SKILL.md` |
| OAuth / OIDC / redirect_uri / PKCE | `oauth-oidc-misconfiguration/SKILL.md` |
| SAML / SSO / Assertion / metadata | `saml-sso-assertion-attacks/SKILL.md` |
| Clickjacking / frame / iframe | `clickjacking/SKILL.md` |
| CRLF / %0d%0a / response splitting | `crlf-injection/SKILL.md` |
| Password spray / credential / 喷洒 | `credential-attack/SKILL.md` |
| Validate / triage / 验证 / 去重 / 7问 | `triage-validation/SKILL.md` |

---

## 安全约束（铁规）

违反任何一条 → 立刻停止，不做辩解。

### 速率限制

| 约束 | 数值 |
|------|------|
| 最大请求速率 | **1 req/s**（间隔 ≥1 秒）|
| 同日同一目标上限 | **500 次/天** |
| 最大并发 | **5** |
| curl 内置参数 | `--max-time 10 --limit-rate 100K` |
| 断路器 | 连续错误 >10 次 → 自动暂停 **5 分钟** |

### 攻击范围

- ✅ 仅 scope 内资产
- ✅ 仅用户明确授权的域名（逐次会话确认）
- ✅ 主动行动前预检输出：目标 URL + 请求数 + 预期影响 → 等用户确认
- ❌ 不对 scope 外域名发包
- ❌ 不扫内网/端口
- ❌ 不扫未授权子域名

### 数据安全

| 规则 | 限额 |
|------|------|
| 确认漏洞所需用户数据 | **≤3 条**，到量立刻停 |
| 发现数据泄露 | **立刻停止**，不扩大 |
| 用户数据存储 | **绝不**存在本地 |
| PoC 中 PII | **脱敏**（前 2+后 2 位，或 SHA256 指纹）|

### 禁止行为

- ❌ DoS / 并发 >5 / 无限循环 / 无限递归
- ❌ 修改/删除/覆盖他人数据
- ❌ 扫描内网端口/服务
- ❌ 上传 webshell 到生产环境
- ❌ 构建/分发攻击工具（exploit framework / C2 / 恶意软件）
- ❌ 供应链投毒（NPM/PyPI/GitHub Actions 注入）
- ❌ 绕过验证码/人机验证
- ❌ 绕过 MFA/2FA
- ❌ 暴力破解真实用户账号
- ❌ 使用公共 DNSLog 平台（必须用厂商平台或自建 interactsh）
- ❌ 环境变量缺失时猜测/替代/硬编码（必须中止）

### 合规

- 所有测试在 SRC 授权范围内进行
- 发现漏洞先通知，不私自利用
- 报告注明测试方法和工具
- 遵守目标所在国家/地区网络安全法律（CFAA / 计算机滥用法 / 网络安全法）
- 所有 API Key/Token 通过环境变量传入 — **绝不硬编码**
- 缺失必需环境变量 → 中止，不做任何假设

---

## 配置（.env）

```bash
# 必填
GPT5_API_KEY=sk-xxx                    # LLM 提供商（GPT-5.5 或兼容）

# 可选 — HackerOne API
H1_USERNAME=你的用户名
H1_TOKEN=你的Token

# 可选 — Burp Suite MCP 集成
BURP_MCP_TOKEN=你的BurpToken
BURP_MCP_HOST=127.0.0.1
BURP_MCP_PORT=9444

# 可选 — 备用 LLM
LONGCAT_API_KEY=ak_xxx                 # 龙猫-2.0（1.6T MoE, 1M 上下文）

# 运行模式
AIMY_MODE=veteran                      # veteran（老鸟）| rookie（菜鸟）
AIMY_SCENE=bounty                      # bounty（赏金）| pentest | redteam | auto-pentest
AIMY_TELEMETRY_ENABLED=false           # 内部质量追踪（静默）
```

---

## Agent 系统 — 专项猎手

AIMY 针对不同漏洞类启动专项子 Agent：

| Agent | 专攻 | 核心工具 |
|-------|------|----------|
| `ssrf-hunter` | SSRF 检测 | OOB + interactsh + 绕过 |
| `sqli-hunter` | SQL 注入 | 布尔、时间、报错、OOB |
| `xss-hunter` | XSS | 反射、存储、DOM |
| `idor-hunter` | IDOR/BOLA | 对象级越权 |
| `rce-hunter` | RCE | SSTI、反序列化、CMDi、XXE |
| `validator` | 确定性验证 | curl 验证 + 8 问门 |
| `coordinator` | 多 Agent 编排 | 并行挖洞调度 |

---

## 文档索引

| 文件 | 内容 | 行数 |
|------|------|------|
| [README.md](./README.md) | 本文件 — 概述、用法、模式、安全规则 | ~450 |
| [SKILL.md](./SKILL.md) | Fusion-router 四源调度中枢（53KB） | 1,033 |
| [INDEX.md](./INDEX.md) | 完整技能索引 + 交叉引用 | ~600 |
| [QUICKSTART.md](./QUICKSTART.md) | 快速入门手册（含每步清单） | ~200 |
| [CLAUDE.md](./CLAUDE.md) | Agent 身份定义、约定、技术栈、优先级 | ~400 |

## 许可证

MIT — 各 Skill 文件见各自许可证。
