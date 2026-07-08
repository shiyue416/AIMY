# AIMY v3.0 — AI 漏洞赏金猎手框架

<p align="center">
  <strong>180+ 攻击技能 &middot; 120+ Python 检测器 &middot; 3,000+ H1 报告 &middot; 50,000 WooYun 案例</strong><br>
  四源融合 — HackSkills · Anthropic · src-hunter · 洺熙注入<br>
  <sub>七阶段挖洞管线 · 35 触发词自动加载 · GitHub 全站 14 项目红线对比最优 (45/50)</sub>
</p>

---

## 快速开始

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
cp .env.example .env          # 编辑填入 API Key（见下方配置章节）
pip install -r aimy/requirements.txt

# 开始挖洞
python aimy.py                              # 交互模式
python aimy.py --target example.com         # 目标模式
python aimy.py -q "hunt example.com"        # 一句话模式
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

## 架构

```
aimy/                          Python 框架
├── core/                      调度器、ReAct 循环、状态机、事件总线
├── tools/                     120+ 漏洞检测器（BaseDetector 模板方法）
│   ├── ssrf_detector.py       SSRF + OOB/interactsh 集成
│   ├── sqli_blind.py          布尔/时间盲注 SQLi
│   ├── xss_detector.py        反射/存储/DOM XSS + 浏览器验证
│   ├── ssti_detector.py       SSTI（20+ 模板引擎）
│   ├── jwt_detector.py        JWT alg:none、弱密钥、kid 注入
│   ├── race_condition.py      TOCTOU 并发引擎
│   ├── deser_weaponizer.py    Java/Python/PHP 反序列化链
│   └── ...                    115+ 更多检测器
├── memory/                    飞轮：FeedbackDB、EVX 进化引擎、战报
├── llm/                       多模型客户端（GPT-5.5、龙猫、Claude）
├── safety/                    安全门禁、scope 校验、审计追踪
├── skills/                    Skill 加载器、注册表、路由、格式化
├── references/                参考文件加载器（按关键词索引、按需加载）

skills/                        180 攻击方法论技能
├── ssrf-server-side-request-forgery/    SKILL.md + SCENARIOS.md + BYPASS.md
├── sqli-sql-injection/                  SKILL.md + BLIND.md + OOB.md + UNION.md
├── xss-cross-site-scripting/            SKILL.md + DOM.md + CSP_BYPASS.md
└── ...                                  176 更多技能目录

anthropic-skills/              8,946 防御/取证/合规技能
references/                    5,891 参考文件
├── hackerone-reports/          3,029 份已公开 H1 报告（按漏洞类索引）
├── payload-kit/                52 个专项 Payload 集合
├── playbooks/                  68 个攻击剧本
└── nuclei-templates-ai/        自动生成的 Nuclei 模板
```

---

## 使用 — 七阶段挖洞管线

每次挖洞遵循确定性七阶段流程，每阶段有入口/出口关卡。

### Phase 1：接单（5 分钟）

Scope 校验、规则加载、时间盒设定。

```bash
/recon target.com          # 触发 Phase 1→2
python aimy.py --target target.com --scope-only   # 手动 scope 检查
```

### Phase 2：侦察 — 六维被动（零发包）

**不向目标发任何包。** 所有数据来自第三方数据源。

| 维度 | 数据源 | 覆盖率 |
|------|--------|--------|
| 1. 子域名被动 | crt.sh、Chaos、subfinder、amass（-passive） | 85-92% |
| 2. 排列变异 | dnsgen（后缀）、alterx（NLP 分词） | 1→50 倍放大 |
| 3. 图标关联 | mmh3 hash → FOFA icon_hash / Shodan http.favicon | 跨资产发现 |
| 4. ASN/IP 反查 | asnmap、amass intel、bgp.he.net、RADB whois | 网络级关联 |
| 5. CSP 情报 | CSP 响应头解析 → 可信域名列表 → httpx 验活 | 免费子域名 |
| 6. JS 源码还原 | .js.map → source-map-unpack → TS 源码 → 端点+凭据 | 源码级攻击面 |

```bash
/recon target.com                           # 全部六个维度
/favicon-hunt --url https://target.com      # 仅维度三
/asn-discovery --org "Target Corp"          # 仅维度四
/csp-intel --url https://target.com         # 仅维度五
/js-sourcemap --recon-dir recon/target.com  # 仅维度六
```

### Phase 3：枚举 — 主动探测

限速主动枚举，发包前过安全门禁。

```bash
/hunt target.com                    # 触发 Phase 3→4
/hunt target.com --vuln-class ssrf  # 只测 SSRF
```

### Phase 4：狩猎 — 信号→剧本→工具 三级调度

1. **信号检测** — 参数名、HTTP 头、响应模式
2. **剧本选择** — 把信号映射到对应的 Skill + 工具
3. **工具执行** — 用正确的 Payload 运行 Python 检测器

```bash
# 按漏洞类定向
/hunt target.com --vuln-class idor
/hunt target.com --vuln-class sqli
/hunt target.com --vuln-class ssti

# 全覆盖（26 类漏洞，每类 ≥25 次，≥90 分钟）
/hunt target.com --autonomous
```

### Phase 5：验证 — 8 问门 + 4 验收关

每个发现必须通过：

| 问# | 问题 | 不通过则 |
|-----|------|----------|
| Q1 | 有实际影响吗？ | 否决 |
| Q2 | 影响类型在程序接受列表里吗？ | 否决 |
| Q3 | 根因在 scope 资产上吗？ | 否决 |
| Q4 | 能稳定复现吗？ | 否决 |
| Q5 | 有没有更严重的利用路径？ | 升级 |
| Q6 | 证据中 PII 已脱敏？ | 修正 |
| Q7 | 违反任何红线规则？ | 否决 |
| Q8 | 是重复提交吗？ | 去重 |

4 验收关：证据完整性、影响真实性、合规性、脱敏。

```bash
/validate           # 执行 8 问门
```

### Phase 6：报告 — 模板驱动

生成可直接提交的报告，包含：
- 漏洞概述
- 技术分析（根因、触发条件、攻击面）
- 复现步骤 / PoC
- 影响评估
- 修复建议

```bash
/report             # 生成所有已确认发现的报告
/report bounty      # 赏金平台格式（H1/Bugcrowd/Intigriti）
/report pentest     # 渗透测试交付格式
```

### Phase 7：飞轮 — 自动进化

记录技法结果、触发 Skill 升级、刷新战报。

```bash
python -m aimy.memory.flywheel        # 手动跑飞轮
python -m aimy.memory.session_brief   # 查看本周高命中技法排行
```

---

## Skill 自动加载系统

每种漏洞类都有触发词表。当 AI 在用户输入或目标响应中检测到匹配关键词时，对应 Skill 在**生成任何 payload 之前**自动加载。

**硬约束：禁止凭记忆生成 payload — 一切来自 Skill 文件。**

| 触发词 | 自动加载 Skill |
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
| [README.md](./README.md) | 本文件 — 概述、用法、模式、安全规则 | ~500 |
| [QUICKSTART.md](./QUICKSTART.md) | 快速入门手册（含每步清单） | ~200 |
| [DISCLAIMER.md](./DISCLAIMER.md) | 免责声明 — 授权范围、操作红线、责任限制 | ~120 |
| [SKILL.md](./SKILL.md) | Fusion-router 四源调度中枢（53KB） | 1,033 |
| [INDEX.md](./INDEX.md) | 完整技能索引 + 交叉引用 | ~600 |
| [CLAUDE.md](./CLAUDE.md) | Agent 身份定义、约定、技术栈、优先级 | ~400 |

---

## 免责声明

> 完整条款见 [DISCLAIMER.md](./DISCLAIMER.md)。**本工具仅供合法授权安全测试及教育用途。使用即视为同意以下全部条款。**

### 授权范围

本工具仅可用于：

- ✅ 你**拥有**或已获得**书面授权**的资产
- ✅ Bug Bounty / SRC 平台明确列入 scope 的目标
- ✅ 已签署 RoE（交战规则）的渗透测试项目
- ✅ CTF 竞赛、自有基础设施、实验靶机

### 明确排除

本工具**不包含**且**不用于**：

- ❌ 针对未授权目标的漏洞利用武器化
- ❌ 后渗透 / 持久化 / 横向移动
- ❌ 恶意软件或 C2 框架开发
- ❌ 大规模未授权扫描
- ❌ 凭据填充 / ATO 自动化
- ❌ 供应链投毒
- ❌ 任何违反 CFAA / 英国《计算机滥用法》/《中华人民共和国网络安全法》等法律法规的行为

### 操作红线

以下规则来自实战经验，效仿 src-hunter 标准：

| 场景 | 红线 |
|------|------|
| SQL 注入 | 探到库名/版本即停，**不 dump 数据** |
| IDOR / 越权 | 取 1-3 条样本即停，**不批量拉取** |
| RCE | 只跑 `id` / `whoami` / `uname -a` |
| 任意文件读取 | 读到 `root:x:` 即停，**不读 /etc/shadow** |
| 泄露凭据 | 仅做一次身份验证调用，**不连接生产环境** |
| 挖到数据 | **立刻停止**，不扩大获取范围 |
| 账号测试 | 用自己注册的两个号互测，**不碰他人账号** |
| Webshell / dump | 本地保存，报告后**立刻删除**，**不 push 到 GitHub** |
| PoC 证据 | 所有 PII 脱敏（前2后2位或 SHA256 指纹）|

### 用户责任

使用本工具即表示你确认：

- **你对你使用本工具的所有行为负全部责任**。"AI 做的"不构成法律辩护理由。
- 你有责任确保对目标拥有授权。**不确定是否在 scope 内 → 停止并书面确认后再行动。**
- 你遵守目标所在平台的规则、scope 限制、测试频率限制。
- 你不会绕过本工具内置的安全门禁（速率限制、只读模式、断路器）。
- 你不会直接提交纯 AI 生成的报告。所有发现必须经过人工验证。
- 部分 SRC 平台（360SRC 等）明文规定：**纯 AI 报告直接驳回，累计 ≥5 条拉黑账号。**

### 责任限制

- 本工具按"**现状**"提供，不保证发现所有漏洞，也不保证发现均为真实漏洞。
- 本工具作者**不承担**因使用或误用本工具导致的任何直接或间接损失，包括但不限于：安全告警、IP 封禁、法律追责、数据泄露、业务中断。
- 使用本工具可能触发目标系统的安全告警，你应自行评估风险。

---

## 许可证

MIT — 各 Skill 文件见各自许可证。
