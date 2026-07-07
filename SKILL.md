---
name: fusion-router
description: >-
  Universal security skill dispatcher — single entry point routing to all 4 sources:
  HackSkills (101 attack skills + 71 Python tools), Anthropic Cybersecurity (817
  defense/forensics/compliance skills), src-hunter (52MB methodology/payloads/H1 reports),
  Mingxi injection layer (Hook + Rules context). Load FIRST — it decides which source for
  which task.
---

# FUSION ROUTER — 四源统一调度

## 一句话

**HackSkills = 攻击  ·  Anthropic = 防御  ·  src-hunter = 深度  ·  Python = 执行**

---

## 0. 快速决策：你的任务属于哪一类？

```
用户说的话                              → 去哪个源
──────────────────────────────────────────────────────────
挖洞/找漏洞/SRC/众测/渗透/CTF攻击        → 统一七阶段主流程（见 🔴）
取证/内存镜像/磁盘分析/时间线             → Anthropic (只有它有)
恶意软件/样本分析/C2/沙箱                 → Anthropic (只有它有)
威胁情报/APT/IOC/狩猎                     → Anthropic (只有它有)
SOC/告警/SIEM规则/SOAR剧本                → Anthropic (只有它有)
钓鱼/社工/BEC                            → Anthropic (只有它有)
勒索软件/加密/支付追踪                   → Anthropic (只有它有)
云安全/AWS/Azure/GCP/K8s日志             → Anthropic (只有它有)
合规/NIST/CMMC/ISO                       → Anthropic (只有它有)
供应链/SBOM/依赖混淆                     → HackSkills(攻击) + Anthropic(防御)
资产收集/子域名/端口/爬虫                 → HackSkills + Python爬虫
写报告/H1模板                            → HackSkills + src-hunter
分析/检测/实施/部署/配置/构建             → Anthropic (动词=过程类)
```

---

## 1. 四源独有能力全图

```
┌─────────────────────────────────────────────────────────────────┐
│                      FUSION ROUTER                              │
│                                                                 │
│  源1: HackSkills (四月)      源2: Anthropic    源3: src-hunter  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ 101 攻击技能 MD   │  │ 817 过程技能 MD   │  │ 52MB 深度资源  │  │
│  │ 71 Python 工具    │  │ 6 框架映射        │  │ Phase 0-7    │  │
│  │ 菜鸟/老鸟模式     │  │ agentskills.io    │  │ Payload库    │  │
│  │ 全攻击链自动化    │  │ MITRE+NIST+ATLAS │  │ H1报告案例   │  │
│  │ WAF绕过引擎       │  │ D3FEND+AI RMF+F3 │  │ 字典+模板    │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
│       攻击视角                防御+合规视角           资源+方法    │
│                                                                 │
│  源4: 洺熙注入层 (可选)                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Hook场景识别 + Rules授权 + 新手指南                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 不存在重叠 — 四个源各占一个维度

| 能力 | HackSkills | Anthropic | src-hunter | 洺熙 |
|------|:----------:|:---------:|:----------:|:----:|
| Web/API攻击方法论 | ✅ 101 | 少量(~30) | — | — |
| 可执行Python工具 | ✅ 71 | ❌ | ❌ | ❌ |
| 二进制/PWN/内核 | ✅ 20+ | ❌ | ❌ | ❌ |
| 密码学攻击 | ✅ 6 | ❌ | ❌ | ❌ |
| AD/Kerberos | ✅ 6 | 少量 | ❌ | ❌ |
| 移动安全 | ✅ 3 | 少量 | ❌ | ❌ |
| Web3/智能合约 | ✅ 3 | 少量 | ❌ | ❌ |
| 数字取证 | ❌ | ✅ 76+ | ❌ | ❌ |
| 恶意软件分析 | ❌ | ✅ 100+ | ❌ | ❌ |
| 威胁情报 | ❌ | ✅ 80+ | ❌ | ❌ |
| SOC/检测工程 | ❌ | ✅ 96+ | ❌ | ❌ |
| 云安全 | ❌ | ✅ 30+ | ❌ | ❌ |
| 合规审计 | ❌ | ✅ 12+ | ❌ | ❌ |
| 钓鱼/社工 | ❌ | ✅ 20+ | ❌ | ❌ |
| 勒索软件 | ❌ | ✅ 15+ | ❌ | ❌ |
| 6框架映射 | ❌ | ✅ MITRE+NIST+ATLAS+D3FEND+AI RMF+F3 | ❌ | ❌ |
| Payload字典 | ❌ | ❌ | ✅ 52MB | ❌ |
| H1报告案例 | ❌ | ❌ | ✅ | ❌ |
| Phase 0-7方法论 | ❌ | ❌ | ✅ | ❌ |
| 菜鸟/老鸟/自动渗透 | ✅ mode.py | ❌ | ❌ | ❌ |
| Hook场景注入 | ❌ | ❌ | ❌ | ✅ |
| 新手指南 | ❌ | ❌ | ❌ | ✅ |

---

## 2. 路由决策流

```
你说任意一句话
      │
      ▼
┌─────────────┐
│ 判断关键词   │
└──┬──┬──┬───┘
   │  │  │
   ▼  ▼  ▼
  🔴  🔵  🟢
 攻击向 防御向 支持向
   │     │     │
   ▼     ▼     ▼
```

### 🔴 攻击向路由 — 统一七阶段主流程

用户说"挖洞/SRC/找漏洞/测目标"后，自动走以下流程：

```
         ┌───────────────────────────────────────────────────┐
         │  用户说"挖洞/SRC/众测" + 给出目标                  │
         │  ↓ 先过 Phase 0 全局红线，不过不进任何后续阶段     │
         └──────────────┬────────────────────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 0: 全局红线（全程适用）         │
         │   7条红线，违反任一条立即停止          │
         └──────────────┬───────────────────────┘
                        ▼  ↓ 全部通过 ↓
         ┌──────────────────────────────────────────┐
         │ Phase 1: Intake（接单） ← B(src-hunter)   │
         │   Scope / 规则 / 时间盒 checkpoint        │
         └──────────────┬───────────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 2: Recon（被动侦察） ← E/D(六维) │
         │   零发包，≥3维度资产收集                │
         └──────────────┬───────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 3: Enum（主动探测） ← A(四月工具) │
         │   端口/指纹/目录/参数，≤1 req/s         │
         │   ⚠️ 进入前必须 pre-flight 确认        │
         └──────────────┬───────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 4: Hunt（漏洞探测） ← B+A       │
         │   信号→playbook→工具 三级映射          │
         │   ├─ 命中 → 证据留存 → 入Phase5       │
         │   ├─ WAF  → 02-bypass-toolkit        │
         │   └─ 卡壳 → 04-control-gap-hunting   │
         │   ⚠️ 数据安全红线全程生效              │
         └──────────────┬───────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 5: Validate（验证门） ← D(七问门) │
         │   Q1-Q8 + 4验收门，一票否决            │
         └──────────────┬───────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 6: Report（提交） ← B+D         │
         │   合规红线 + 模板 + CVSS 4.0          │
         │   ⚠️ 所有 PII 脱敏，必读 compliance   │
         └──────────────┬───────────────────────┘
                        ▼
         ┌──────────────────────────────────────┐
         │ Phase 7: Flywheel（飞轮复盘） ← D(EVX)│
         │   technique入库 → SKILL.md注入 →      │
         │   session_brief刷新（含你的命中记录）   │
         └──────────────────────────────────────┘

         后渗透/取证 ← C(Anthropic)
         仅在Phase 4命中RCE/Shell/内网入口后按需加载
```

---

#### Phase 0 · 全局红线 🔒（全程适用，违反任一条立即终止）

**🚫 禁止行为（触碰即停，不做任何辩解）：**
```
[ ] ❌ DoS / 并发 > 5 / 无限循环 / 无限递归
[ ] ❌ 修改/删除/覆盖他人数据
[ ] ❌ 扫描内网端口/服务（无授权）
[ ] ❌ 上传 webshell 到生产环境
[ ] ❌ 遇到验证码/人机验证尝试绕过
[ ] ❌ 对非授权目标发起任何请求
[ ] ❌ 绕过多因素认证（MFA/2FA）
[ ] ❌ 针对真实用户账号做暴力破解
[ ] ❌ 使用公共 DNSLog 平台（必须用厂商平台或自建 interactsh）
```

**速率：** ≤1 req/s · 单目标 ≤500 req/day · 并发 ≤5 · curl `--max-time 10 --limit-rate 100K`

**数据安全：**
```
[ ] 单次测试最多获取 3 条用户数据，验证即停
[ ] 发现数据泄露后立即停止，不扩大获取范围
[ ] 绝不存储用户真实数据到本地文件
[ ] 所有测试限 SRC 授权范围内
[ ] 发现漏洞后优先通知，不私自利用
```

---

#### Phase 1 · Intake（接单） ← B(src-hunter)

**入口信号**：用户首次给出目标/程序名/URL

**Checkpoint（四项缺一不进Phase 2）**：
```
[ ] In-scope：可测资产逐条列明
[ ] Out-of-scope：禁测项逐条列明
[ ] 规则：payout / disclosure / safe-harbor / 测试header
[ ] 时间盒：6h / 单日 / HVV / 月度
```

Timebox 优先策略 → Read `references/methodology/05-srctimebox-priority.md`

---

#### Phase 2 · Recon（被动侦察，零发包） ← E(CLAUDE.md六维) + D(彦工具)

**六维覆盖**：

| 维度 | 来源 |
|------|------|
| ① 子域名被动 | crt.sh + Chaos + subfinder + amass(-passive) |
| ② 排列变异 | dnsgen / alterx / 内置引擎 |
| ③ 图标关联 | mmh3 hash → FOFA / Shodan |
| ④ ASN/IP反查 | asnmap + bgp.he.net + RADB |
| ⑤ CSP反向情报 | CSP响应头 → 可信域名 → httpx验证 |
| ⑥ JS源码还原 | .js.map → source-map-unpack → 端点+凭据 |

**约束**：默认 passive-only（零发包），需 `--active` 才发起主动请求。
**MUST 输出**：不发包得到的资产清单，来源 ≥3 种。

**Burp MCP 补充**（只读，不发包）：
| 操作 | Burp MCP 工具 |
|------|--------------|
| 查看历史流量 | `proxy_history` / `sitemap_query` |
| 被动信息收集 | `passive_intel` — 自动扫描 API Key/Token/JWT/内网IP |

---

#### Phase 3 · Enum（主动探测，限速发包） ← A(四月工具)

**MUST 输出**：活资产矩阵——`域→端口→服务→指纹→JS endpoint`

| 操作 | 四月工具 |
|------|---------|
| 端口扫描 | `python -c "from aimy.tools.active_prober import scan; scan('target')"` |
| 目录枚举 | `python -c "from aimy.tools.crawler import crawl; crawl('target')"` |
| 信息收集 | `python -c "from aimy.tools.attack_surface import analyze; analyze('target')"` |
| 参数挖掘 | `python -c "from aimy.tools.param_miner import mine; mine('target')"` |
| WAF识别 | `python -c "from aimy.tools.waf_bypass import detect_waf; detect_waf('target')"` |

**条件触发 Read**：指纹含国产OA/中间件 → Read `dictionaries/chinese-srcfingerprints.md` + `dictionaries/default-credentials-cn.md`

**Burp MCP 补充**（限速发包）：
| 操作 | Burp MCP 工具 |
|------|--------------|
| 手动发包 | `http_send_request` |
| 参数枚举 | `intruder_send` |
| 全站爬取 | `scanner_start_crawl` ⚠️ pre-flight 必需 |

**速率限制**（Phase 0 精度版）：
```
≤1 req/s          ← curl --max-time 10 --limit-rate 100K
≤500 req/day      ← 超过即停
并发 ≤5           ← 禁止大规模并发
```

---

#### Phase 4 · Hunt（漏洞探测） ← B(选playbook) + A(执行工具)

```
Phase 3 活资产矩阵
       │
       ▼
  观察入口信号 ─────────────────┐
       │                        │
       ▼                        ▼
  选 playbook(B)            无信号→ Control Gap Hunting
       │                     (04-control-gap-hunting.md)
       ▼
  Read playbook(B) ← 不准凭记忆
       │
       ▼
  挑参数频率表 → 发包检测(A)
       │
       ├─ 命中 → 证据留存(03-evidence-discipline) → 入Phase5候选
       ├─ WAF拦截 → 02-bypass-toolkit.md 决策树
       └─ 卡壳   → 04-control-gap-hunting.md
```

**Burp MCP 通道**（按场景选工具）：
| 场景 | Burp MCP 工具 |
|------|--------------|
| 调试 | `repeater_send` |
| SQLi | `http_send_request` + `analyze_response` |
| XSS | `repeater_send` + `analyze_find_reflected` |
| SSRF | `collaborator_*` |
| IDOR | `auth_diff` 三角色 |
| 竞态 | `http_race` |
| WAF | `intruder_*` + `http_fuzz` |
| 参数 | `analyze_insertion_points` |
| 扫描 | `scanner_start_audit` ⚠️ pre-flight |

**入口信号 → playbook 映射**：

| 信号 | 读 Playbook(B) | 跑工具(A) |
|------|---------------|-----------|
| Actuator/Swagger/默认端口 | `unauth-access.md` | `aimy/tools/attack_surface.py` |
| .git/.svn/heapdump/路径列举 | `info-disclosure.md` | — |
| 用户态ID可遍历/任意X越权 | `arbitrary-x-authz.md` | — |
| 密码重置/支付/验证码/订单/提现 | `logic-flaws/00-index.md` | `aimy/tools/biz_logic_scanner.py` |
| OAuth/SAML/JWT/redirect_uri | `oauth-saml-jwt/00-index.md` | `aimy/tools/jwt_detector.py` |
| REST API/BOLA/Mass Assignment | `api-rest/00-index.md` | — |
| 用户输入进DB | `sqli.md` | `aimy/tools/sql_injection.py` |
| 反序列化/SSTI/XXE/原型链/框架RCE | `rce/00-index.md` | `aimy/tools/deserialization_detector.py / ssti_detector.py` |
| URL入参/缓存/Host注入 | `ssrf-cache-host/00-index.md` | `aimy/tools/ssrf_detector.py` |
| 文件路径入参/LFI/RFI | `path-traversal/00-index.md` | `aimy/tools/lfi_scanner.py` |
| 上传点+解析漏洞 | `file-upload/00-index.md` | — |
| 用户输入回显HTML/JS | `xss/00-index.md` | `aimy/tools/xss_detector.py` |
| 反代+Content-Length/TE | `http-smuggling.md` | — |
| GraphQL endpoint/introspection | `graphql.md` | `aimy/tools/graphql_scanner.py` |
| 并发/TOCTOU | `race-conditions.md` | `aimy/tools/race_condition.py` |
| ReDoS/资源不限速/算法爆炸 | `dos.md` | — |
| APK/IPA/移动端 | `mobile.md` | — |
| LLM agent/prompt入口/工具调用 | `llm-prompt-injection/00-index.md` | — |
| 已拿到shell/凭据/内网 | `intranet-postexp/00-index.md` | → 调C(Anthropic) |

**两步 Read 模式**：目录式 playbook（`rce/` / `oauth-saml-jwt/` / `ssrf-cache-host/` / `api-rest/` / `logic-flaws/` / `file-upload/` / `path-traversal/` / `xss/` / `llm-prompt-injection/` / `intranet-postexp/`）先读 `00-index.md` 定位子文件，再读具体场景子文件。

**通用方法论**（卡壳时读，不要预加载）：
- 不知道下一步打什么 → `01-attack-priority.md`
- 被WAF拦 → `02-bypass-toolkit.md`
- 怀疑证据链 → `03-evidence-discipline.md`
- 找不到漏洞点 → `04-control-gap-hunting.md`

**原创脑洞锦囊**（卡住或没思路时翻）：
- 时光机考古/WayBack翻旧版 → `references/SRC_终极脑洞.md`
- 七种业务逻辑非对称思维 → `references/业务逻辑拓展骚思路.md`
- 例行轮换：session_brief 每日冷门技巧
- **排除记录**（防重复尝试）→ `彦的h1飞轮/06_排除记录.md`


**数据安全红线**（Phase 0 精度版）：
```
[ ] 最多获取 3 条用户数据，验证即停
[ ] 发现数据泄露立即停止，不扩大
[ ] 绝不存储真实数据到本地文件
[ ] SQLi 探测到库名/版本即停，不 dump
[ ] IDOR/越权 取 1-3 条样本即停
[ ] RCE 只跑 read-only 命令(id/whoami/uname -a)
[ ] OOB 验证用厂商平台或自建，不用公共 DNSLog
```

**证据纪律**：命中后立即保存 HTTP 包/截图/视频 → 入 Phase 5 候选

---

#### Phase 5 · Validate（验证门） ← D(七问门)

**Q1-Q8 顺序执行，一票否决**：
```
Q1: 攻击者能立刻 step by step 复现吗？→ 写不出HTTP包就停
Q2: 影响在程序的接受列表里吗？        → 不在就停
Q3: 根因在scope资产上吗？            → 不在就停
Q4: 需要攻击者不可能拿到的权限吗？     → 管理员才能触发就停
Q5: 这是已知/已接受行为吗？          → 是就停
Q6: 能证明实际影响吗？               → 不能就降级
Q7: 在禁止提交清单里吗？             → 在就停
Q8: 身份校验——换个session还能复现吗？→ 不能就停
```

**4验收门（全过才写报告）**：
```
Gate 0: Reality Check — 30s，确认真实复现
Gate 1: Impact        — 2min，攻击者拿到了什么？
Gate 2: Dedup         — 5min，搜Hacktivity/GitHub/Google
Gate 3: Report Quality— 10min，标题/步骤/证据/CVSS
```

详见 `Skill("triage-validation")`。

**Burp MCP 补充**：
| 操作 | Burp MCP 工具 |
|------|--------------|
| 复现漏洞 | `repeater_send` |
| 响应对比 | `analyze_diff` |
| 证据存档 | `organizer_send` |

---

#### Phase 6 · Report（提交） ← B(src-hunter模板) + D(合规红线)

**MUST 流程**：
1. Read `references/compliance.md` 合规红线（不准跳）
2. Read `references/templates/report-submission.md` 取模板
3. 三段式输出：
   ```
   标题：[漏洞类型] in [端点] allows [攻击者] to [影响]
   步骤：每步可执行，附HTTP包/curl/截图
   影响：CVSS 4.0 vector + 业务影响段
   ```

**Burp MCP 补充**：
| 操作 | Burp MCP 工具 |
|------|--------------|
| 导出报告 | `scanner_generate_report` |
| 存档证据 | `organizer_send` |

**PII 脱敏强制要求**：
```
[ ] 手机号/邮箱/用户名 → 留前2后2，中间打码
[ ] Token/Cookie → 留前2后2，必要时附 sha256 指纹
[ ] IP/内网地址 → 打码末段
[ ] 报告中所有敏感信息遵循最小暴露原则
```

---

#### Phase 7 · Flywheel（飞轮复盘） ← D(EVX)

**Burp MCP 补充**：
| 操作 | Burp MCP 工具 |
|------|--------------|
| 生成检测规则 | `bcheck_create` |
| 部署 BCheck | `bcheck_import` |

**自动动作**：
```
1. 本finding技法提取 → 写入 techniques.jsonl（你自己的命中记录）
2. 对应 SKILL.md 自动注入飞轮进化技法章节（FLYWHEEL_APPEND）
3. session_brief 刷新本周优先技法排序（你的成功经验可能排第一）
```

**飞轮数据目录** `彦的h1飞轮/`：
| 文件 | 说明 |
|------|------|
| `00_飞轮运转说明.md` | 飞轮整体运转逻辑 |
| `01_本机路径速查.md` | 本地工具/脚本路径速查 |
| `02_API_Key配置.md` | API Key 配置与安全管理 |
| `03_漏网工具补充.md` | 框架未覆盖的补充工具 |
| `04_AIMY自研工具层.md` | 自研工具层说明 |
| `05_举一反三机制.md` | 成功技法→变体→同类端点应用 |
| `06_排除记录.md` | 已排除路径记录，防重复尝试 |
| `116类最佳技法.md` | 110+ 已排序最佳技法列表（飞轮实时刷新） |
| `32个顶级资源库.md` | 外部顶级资源库索引 |

---

#### 后渗透/取证 ← C(Anthropic)

**⚠️ 进入条件：命中 RCE/Shell/内网入口后，先通知用户确认**

```
输出以下内容给用户，等待确认后才加载 Anthropic 技能：
  ⚡ Phase 4 命中：<RCE / Shell / 内网入口>
  📦 已获得的访问级别：<命令执行 / 交互式Shell / 凭据>
  🎯 建议下一步：<提权 / 横向 / 持久化 / 取证>
  🔧 将加载：<具体的 Anthropic 技能清单>
```

用户确认后执行，否则不进后渗透阶段。

**可用 Anthropic 技能：**
```
已拿到shell      → linux-privilege-escalation / windows-lateral-movement
已拿到内存       → analyzing-memory-dumps-with-volatility
已拿到流量       → analyzing-network-traffic-with-wireshark
需要横向         → moving-laterally-with-netexec
需要持久化       → operating-sliver-c2 / operating-havoc-c2
需要AD攻击       → active-directory-kerberos-attacks / ntlm-relay-coercion
```

---

**攻击向完整技能索引**（五体系合并，全部已注册，直接可用）：

| 类别 | 可用技能 |
|------|---------|
| **注入类** | `sqli-sql-injection` `xss-cross-site-scripting` `ssrf-server-side-request-forgery` `ssti-server-side-template-injection` `cmdi-command-injection` `xxe-xml-external-entity` `nosql-injection` `crlf-injection` `email-header-injection` `xslt-injection` `csv-formula-injection` `jndi-injection` `expression-language-injection` `dangling-markup-injection` `deserialization-insecure` `open-redirect` |
| **认证授权** | `auth-sec` `authbypass-authentication-flaws` `jwt-oauth-token-attacks` `api-auth-and-jwt-abuse` `api-authorization-and-bola` `idor-broken-object-authorization` `oauth-oidc-misconfiguration` `saml-sso-assertion-attacks` `401-403-bypass-techniques` |
| **API安全** | `api-sec` `api-auth-and-jwt-abuse` `api-authorization-and-bola` `api-recon-and-docs` `graphql-and-hidden-parameters` `graphql-audit` |
| **文件操作** | `upload-insecure-files` `path-traversal-lfi` `file-access-vuln` |
| **业务逻辑** | `business-logic-vulnerabilities` `business-logic-vuln` `race-condition` |
| **协议攻击** | `request-smuggling` `web-cache-deception` `http-host-header-attacks` `http-parameter-pollution` `http2-specific-attacks` `websocket-security` `dns-rebinding-attacks` |
| **客户端** | `cors-cross-origin-misconfiguration` `csrf-cross-site-request-forgery` `csp-bypass-advanced` `clickjacking` `prototype-pollution` `prototype-pollution-advanced` `type-juggling` |
| **侦察收集** | `web2-recon` `recon-and-methodology` `recon-for-sec` `api-recon-and-docs` `graphql-and-hidden-parameters` `graphql-audit` `miniapp-recon` `insecure-source-code-management` `subdomain-takeover` `dependency-confusion` |
| **分类路由** | `api-sec` (API总入口) `auth-sec` (认证总入口) `injection-checking` (注入总入口) |
| **二进制/PWN** | `stack-overflow-and-rop` `heap-exploitation` `format-string-exploitation` `arbitrary-write-to-rce` `kernel-exploitation` `sandbox-escape-techniques` `binary-protection-bypass` `anti-debugging-techniques` `code-obfuscation-deobfuscation` `vm-and-bytecode-reverse` `symbolic-execution-tools` `browser-exploitation-v8` `macos-process-injection` `ghost-bits-cast-attack` |
| **密码学** | `rsa-attack-techniques` `hash-attack-techniques` `classical-cipher-analysis` `lattice-crypto-attacks` `symmetric-cipher-attacks` |
| **AD/内网** | `active-directory-kerberos-attacks` `active-directory-acl-abuse` `active-directory-certificate-services` `ntlm-relay-coercion` |
| **提权/横向** | `linux-privilege-escalation` `windows-privilege-escalation` `linux-lateral-movement` `windows-lateral-movement` `linux-security-bypass` `macos-security-bypass` `tunneling-and-pivoting` `unauthorized-access-common-services` `container-escape-techniques` `kubernetes-pentesting` `waf-bypass-techniques` `reverse-shell-techniques` `windows-av-evasion` |
| **移动** | `android-pentesting-tricks` `ios-pentesting-tricks` `mobile-ssl-pinning-bypass` `mobile-pentest` |
| **Web3** | `web3-audit` `smart-contract-vulnerabilities` `defi-attack-patterns` `meme-coin-audit` |
| **AI/LLM** | `llm-prompt-injection` `ai-ml-security` |
| **方法论** | `hack` `bb-methodology` `bug-bounty` `security-arsenal` `Claude-BugHunter` |
| **审计/扫描** | `api-audit` `cloud-audit` `container-audit` `crypto-audit` `dependency-audit` `iam-audit` `mobile-audit` `owasp-audit` `secrets-audit` |
| **合规** | `hipaa-audit` `pci-audit` `csf-mapping` `privacy-engineering` |
| **防御/检测** | `breach-patterns` `siem-detection` `threat-hunting` `threat-modeling` `incident-triage` `finding-triage` `disk-forensics` `security-comms` |
| **研究/情报** | `vuln-research` `ai-risk-management` `osint-recon` `offensive-osint` |
| **红队/综合** | `red-team-engagement` `redteam-mindset` `redteam-report-template` `web-pentest` |
| **其他** | `credential-attack` `cicd-security` `network-protocol-attacks` `memory-forensics-volatility` `traffic-analysis-pcap` `steganography-techniques` `triage-validation` `report-writing` `web2-vuln-classes` `bb-local-toolkit` `bugcrowd-reporting` `evidence-hygiene` `hunt-dispatch` |
| **外部** | `external` `Claude-BugHunter` `pentest-agents` |

**对应Python工具**（彦/aimy/tools/，108个）：

```
sql_injection.py / sqli_blind.py / sqli_oob.py / sqli_weaponizer.py
xss_detector.py / xss_browser_verify.py / xss_validator.py
html_context_parser.py
ssrf_detector.py / ssrf_pwn.py
cmdi_detector.py
ssti_detector.py
jwt_detector.py / jwt_exploiter.py
deserialization_detector.py / deser_weaponizer.py
nosqli_detector.py
lfi_scanner.py
cors_scanner.py
graphql_scanner.py
proto_pollution.py
race_condition.py / race_profiler.py
biz_logic_scanner.py / biz_logic_v2.py
active_prober.py
auth_bypass.py / auth_engine.py
crawler.py / spa_crawler.py
fuzz_engine.py / smart_fuzzer.py / adaptive_fuzzer.py
param_miner.py / param_classifier.py
payload_engine.py / payload_mutator.py
waf_bypass.py
mitm_proxy.py
oob_server.py
reverse_shell.py
kali_executor.py / kali_toolset.py / kali_capture.py
packet_capture.py
playwright_engine.py / playwright_auth.py
orchestrator.py
reporter.py
attack_surface.py / attack_tree.py
chain_engine.py
constraint_graph.py
knowledge_graph.py / reasoning_engine.py
semantic_diff.py / deviation_oracle.py
flow_reconstructor.py
session_matrix.py / dual_session.py
workflow.py / workflow_tracer.py
response_analyzer.py / response_profiler.py
verification_oracle.py
http_client.py
mode.py
settings.py
```

### Burp MCP 集成（第5通道 — 代号 BP）

Burp Suite Professional 通过 MCP 协议接入，受 Phase 0 全局红线约束。

**风险分级表：**
| 工具 | 发包 | 风险 |
|------|:----:|:----:|
| `proxy_history` / `sitemap_query` | ❌ | 🟢 |
| `analyze_*` / `util_*` | ❌ | 🟢 |
| `collaborator_*` | ✅ DNS | 🟢 |
| `repeater_send` | ✅ | 🟡 |
| `http_send_request` | ✅ | 🟡 |
| `http_fuzz` / `intruder_*` | ✅ 多次 | 🟡 |
| `auth_diff` | ✅ 3次 | 🟡 |
| `http_race` | ✅ 并发 | 🟠 |
| `scanner_start_audit` / `scanner_start_crawl` | ✅ 大量 | 🔴 |
| `bcheck_create` / `bcheck_import` | ❌ | 🟢 |

**红线：** 发包工具自动挂 scope + ≤1 req/s + ≤500/day + 并发≤5
**scanner_start_* 必须过 pre-flight 确认**

> 配套参考: `references/tools/mcp-jshook.md` — MCP JS Hook 工具指南

### 🔵 防御向路由（取证/恶意软件/威胁情报/SOC/云/合规/钓鱼/勒索）

```
用户说 → 直接读 Anthropic 技能文件（HackSkills 完全没有这些域）
```

### 🟢 支持向路由（资产收集/报告）

```
资产收集:
  Skill("web2-recon")           → 子域名+存活+爬虫标准管线
  Python crawler.py             → 动态SPA爬虫
  Python param_miner.py         → 参数挖掘
  Python attack_surface.py      → 攻击面分析

报告撰写:
  Skill("report-writing")       → H1/Bugcrowd模板
  src-hunter references/        → 全部深度资源

验证:
  Skill("triage-validation")    → 7问门 + 4验收门
```

---

## 3. 源优先级规则

同一任务多个源都有覆盖时，按此顺序：

```
挖洞（统一七阶段主流程）:
  1st → B(src-hunter) 定方向        (Intake + 选playbook)
  2nd → A(HackSkills) + BP(Burp MCP) 动手 (Enum/Hunt/发包/调试)
  3rd → D(彦/EVX)     把关           (七问门验证 + 飞轮复盘)
  4th → C(Anthropic)  后渗透支撑      (仅命中RCE/Shell后介入)

取证/IR / 威胁情报 / 恶意软件 / SOC / 云 / 合规 / 钓鱼:
  ONLY → Anthropic

CTF：
  1st → HackSkills skill
  2nd → Python solve_full.py / solve_full2.py

供应链:
  1st → HackSkills dependency-confusion (攻击)
  2nd → Anthropic (防御)
```

---

## 4. Python 工具调用

**快速命令（全部 30 个子命令）**：
```bash
# AIMY 内置工具（无需 main.py，直接通过 aimy 调用）

# 全自动管线
python aimy.py -t <URL> -p longcat --autopilot
python aimy.py -t <URL> -p longcat

# 单项注入检测
python -c "from aimy.tools.sql_injection import check; print(check('<URL>', 'id'))" 
python -c "from aimy.tools.xss_detector import check; print(check('<URL>', 'q'))"
python -c "from aimy.tools.cmdi_detector import check; print(check('<URL>', 'cmd'))"
python -c "from aimy.tools.ssti_detector import check; print(check('<URL>', 'name'))"
python -c "from aimy.tools.ssrf_detector import check; print(check('<URL>', 'url'))"
python -c "from aimy.tools.nosqli_detector import check; print(check('<URL>', 'id'))"
python -c "from aimy.tools.lfi_scanner import check; print(check('<URL>', 'file'))"

# AIMY 统一命令（彦/aimy/）:
常用检测:
  python -c "from aimy.tools.sql_injection import check; print(check('<URL>', 'id'))"
  python -c "from aimy.tools.ssrf_detector import check; print(check('<URL>', 'url'))"
  python -c "from aimy.tools.xss_detector import check; print(check('<URL>', 'q'))"
  python -c "from aimy.tools.auth_bypass import check; print(check('<URL>'))"

侦察:
  python -c "from aimy.tools.attack_surface import analyze; analyze('target')"
  python -c "from aimy.tools.param_miner import mine; mine('target')"

全自动:
  python aimy.py -t <URL>
```
```

---

## 5. 速查调度表

| 用户说 | 第一步 |
|--------|--------|
| "挖洞/SRC/找漏洞" | **Phase 1→7 统一主流程** |
| "SQL注入" | `Skill("sqli-sql-injection")` + `tools/sql_injection.py` |
| "XSS" | `Skill("xss-cross-site-scripting")` + `tools/xss_detector.py` |
| "SSRF" | `Skill("ssrf-server-side-request-forgery")` + `tools/ssrf_detector.py` |
| "条件竞争" | `Skill("race-condition")` + `tools/race_condition.py` |
| "业务逻辑" | `Skill("business-logic-vulnerabilities")` + `tools/biz_logic_scanner.py` |
| "JWT攻击" | `Skill("jwt-oauth-token-attacks")` + `tools/jwt_exploiter.py` |
| "401/403绕过" | `Skill("401-403-bypass-techniques")` |
| "子域名收集" | `Skill("web2-recon")` |
| "验证漏洞" | `Skill("triage-validation")` |
| "内存取证" | Anthropic: `analyzing-memory-dumps-with-volatility` |
| "恶意软件" | Anthropic: `analyzing-malware-behavior-with-cuckoo-sandbox` |
| "APT追踪" | Anthropic: `analyzing-apt-group-with-mitre-navigator` |
| "SOC告警" | Anthropic: `triaging-security-alerts-in-splunk` |
| "AD攻击" | `Skill("active-directory-kerberos-attacks")` |
| "Web3审计" | `Skill("web3-audit")` |
| "审计/代码审计" | `Skill("api-audit")` / `Skill("secrets-audit")` |
| "合规/CMMC/NIST/ISO" | `Skill("csf-mapping")` + Anthropic: `achieving-cmmc-level-2-compliance` |
| "HIPAA" | `Skill("hipaa-audit")` |
| "PCI" | `Skill("pci-audit")` |
| "供应链/Dependency" | `Skill("dependency-audit")` + `Skill("dependency-confusion")` |
| "威胁狩猎" | `Skill("threat-hunting")` + Anthropic |
| "威胁建模" | `Skill("threat-modeling")` |
| "事件响应/IR" | `Skill("incident-triage")` + Anthropic |
| "漏洞研究/CVE" | `Skill("vuln-research")` |
| "SIEM/检测规则" | `Skill("siem-detection")` + Anthropic |
| "红队/对抗模拟" | `Skill("red-team-engagement")` + `Skill("redteam-mindset")` |
| "渗透测试" | `Skill("web-pentest")` |
| "取证/磁盘分析" | `Skill("disk-forensics")` + Anthropic |
| "OSINT/情报" | `Skill("osint-recon")` + `Skill("offensive-osint")` |
| "AI安全/模型" | `Skill("ai-risk-management")` + `Skill("ai-ml-security")` |
| "隐私/GDPR" | `Skill("privacy-engineering")` |
| "安全沟通/报告" | `Skill("security-comms")` |
| "云审计" | `Skill("cloud-audit")` + `Skill("iam-audit")` |
| "容器/K8s审计" | `Skill("container-audit")` + `Skill("kubernetes-pentesting")` |
| "移动审计" | `Skill("mobile-audit")` + `Skill("mobile-pentest")` |
| "OWASP" | `Skill("owasp-audit")` |
| "加密审计" | `Skill("crypto-audit")` |
| "漏洞分诊" | `Skill("finding-triage")` |

---

## 6. 源文件位置

| 源 | 路径 |
|----|------|
| **HackSkills技能** | `.claude/skills/<name>/SKILL.md` |
| **Anthropic技能** | `彦/anthropic-skills/<name>/` |
| **src-hunter 参考库** | `彦/references/` |
| **src-hunter playbooks** | `彦/references/playbooks/` |
| **src-hunter methodology** | `彦/references/methodology/` |
| **src-hunter 合规红线** | `彦/references/compliance.md` |
| **src-hunter H1案例** | `彦/references/h1-reports/by-weakness/` |
| **Python工具 (已合并)** | `Desktop/彦/aimy/tools/` (原四月工具合并至此) |
| **AIMY CLI** | `Desktop/彦/aimy.py` |
| **彦/EVX 飞轮** | `Desktop/彦/` |
| **彦 session_brief** | `.aimy/session_brief.md` |
| **CLAUDE.md** | `.claude/CLAUDE.md` |
| **Burp MCP** | MCP 通道（`mcp__burp__*` 60+工具） |
| **定制技能** | `claude-extra-skills/`（16个 CBB 定制技能） |
| **情报查询** | `aimy/intel_query.py` |
| **飞轮数据** | `彦的h1飞轮/`（8个数据文件：116技法/32资源库/举一反三/...） |
| **技能主索引** | `INDEX.md`（116 Skill 完整列表） |
| **快速入口** | `README.md`（给新手的30秒开始） |
| **CLI入口** | `aimy.py` / `fusion_main.py` |

---

## 7. 操作原则

1. **先分类后加载** — 最大的错误是对取证任务加载攻击技能
2. **挖洞走统一七阶段** — B定方向 → A+BP动手 → D把关 → C后渗透待命
3. **Phase 0 全局红线全程生效** — 违反任一条立即终止
4. **Phase 1 scope checkpoint 不可跳过**
5. **Phase 3 pre-flight 确认不可跳过**
6. **Phase 4 数据安全红线不可逾越** — 最多3条，发现即停
7. **Phase 5 验证门不可跳过**
8. **Phase 6 PII 脱敏强制**
9. **Phase 7 飞轮必须触发**
10. **Burp MCP 受 Phase 0 红线约束** — scanner/crawl 必须 pre-flight
11. **C(Anthropic) 仅在 Phase 4 命中后渗透才介入**
12. **菜鸟模式给解释，老鸟模式给结论，auto-pentest 模式全自动蜂群**

---

## 8. 权威源裁决（Web2 25类漏洞 → Skill 映射）

核心原则：**原始 102 Skill = 权威方法论 (★)，CBB Skill = 执行层/参考 (☆)**

| 漏洞类 | ★ 权威 Skill | ☆ 参考/执行层 | 说明 |
|--------|-------------|--------------|------|
| **XSS** | `xss-cross-site-scripting` | `web2-vuln-classes` §XSS | 原始有 DOM sink + CSP bypass |
| **SQLi** | `sqli-sql-injection` | `web2-vuln-classes` §SQLi | 原始有 blind/OOB/DB 专属 |
| **SSRF** | `ssrf-server-side-request-forgery` | `web2-vuln-classes` §SSRF | 原始有 11 IP bypass 表 |
| **IDOR** | `idor-broken-object-authorization` | `web2-vuln-classes` §IDOR | 原始有完整测试清单 |
| **CSRF** | `csrf-cross-site-request-forgery` | `web2-vuln-classes` §CSRF | 原始有 SameSite/JSON 深度 |
| **Command Injection** | `cmdi-command-injection` | `web2-vuln-classes` §CMDi | 原始有 blind/OOB 深度 |
| **File Upload** | `upload-insecure-files` | `web2-vuln-classes` §Upload | 原始有格式专属 bypass |
| **SSTI** | `ssti-server-side-template-injection` | `web2-vuln-classes` §SSTI | 原始有框架专属 payload |
| **XXE** | `xxe-xml-external-entity` | `web2-vuln-classes` §XXE | 原始有解析器专属深度 |
| **LFI/Path Traversal** | `path-traversal-lfi` | `web2-vuln-classes` §LFI | 原始有 wrapper 链 |
| **Deserialization** | `deserialization-insecure` | `web2-vuln-classes` §Deser | 原始有 Java/PHP/Python 深度 |
| **JWT** | `jwt-oauth-token-attacks` | `web2-vuln-classes` §JWT | 原始有算法混淆完整矩阵 |
| **OAuth/OIDC** | `oauth-oidc-misconfiguration` | `web2-vuln-classes` §OAuth | 原始有 PKCE/state 完整覆盖 |
| **SAML/SSO** | `saml-sso-assertion-attacks` | `web2-vuln-classes` §SAML | 原始有 XSW/signature 剥离 |
| **GraphQL** | `graphql-audit` (CBB) | `graphql-and-hidden-parameters` | CBB 有工具管线, 原始有 schema fuzz |
| **Race Condition** | `race-condition` + `h1_race.py` (CBB) | `web2-vuln-classes` §Race | 原始 TOCTOU 理论, CBB 执行 |
| **Business Logic** | `business-logic-vulnerabilities` | `web2-vuln-classes` §BizLogic | 原始有完整状态机 |
| **HTTP Smuggling** | `request-smuggling` | `web2-vuln-classes` §Smuggling | 原始有 CL.TE/TE.CL/H2.CL |
| **Cache Poisoning** | `web-cache-deception` | `web2-vuln-classes` §Cache | 原始有完整方法论 |
| **Subdomain Takeover** | `subdomain-takeover` | `web2-vuln-classes` §Takeover | 原始有检测指纹库 |
| **Prototype Pollution** | `prototype-pollution` → `prototype-pollution-advanced` | `web2-vuln-classes` §PP | 原始有 gadget 链 |
| **CORS** | `cors-cross-origin-misconfiguration` | `web2-vuln-classes` §CORS | 原始有 preflight 深度 |
| **Open Redirect** | `open-redirect` | `web2-vuln-classes` §Redirect | 原始有完整 bypass |
| **LLM/AI** | `llm-prompt-injection` + `ai-ml-security` | `web2-vuln-classes` §LLM | 原始有 ASI01-ASI10 框架 |
| **MFA Bypass** | `authbypass-authentication-flaws` | `web2-vuln-classes` §MFA | 原始有 7 种 bypass 模式 |

---

## 9. 资产收集九维路由表

| 维度 | 命令 | 工具脚本 | 覆盖 |
|------|------|---------|------|
| 子域名被动 | `/recon` | `recon_engine.sh` → crt.sh + Chaos + subfinder | 85-92% |
| 排列变异 | `/permutation-gen` | `permutation_gen.sh` → dnsgen + alterx + 内置引擎 | 1→50x |
| 图标关联 | `/favicon-hunt` | `favicon_hunt.sh` → mmh3 + FOFA + Shodan | 跨资产 |
| ASN/IP 反向 | `/asn-discovery` | `asn_discovery.sh` → asnmap + amass + bgp.he.net | 网络级 |
| CSP 反向 | `/csp-intel` | `csp_intel.sh` → CSP解析 + csprecon | 可信域 |
| JS 源码还原 | `/js-sourcemap` | `js_sourcemap.sh` → .js.map → TS源码 | 端点级 |
| 小程序资产 | `/miniapp-recon` | `miniapp_recon.sh` → AppID收集+wxapkg解包+API提取 | 微信/支付宝/抖音 |
| 实时证书监控 | `/certstream-watch` | `certstream_watch.sh` → CertStream firehose+秒级新域名 | 秒级·零发包 |
| 实时代码监控 | `/github-watch` | `github_watch.sh` → GitHub代码提交+端点提取 | 预发布资产 |
| CDN 源站 | `/cdn-origin` | `cdn_origin.sh` → DNS历史 + 多地区 | 绕过WAF |

### Autopilot Agent 映射

| Agent | 职责 | 加载 Skill |
|-------|------|-----------|
| `recon-agent` | 资产发现 | `web2-recon` |
| `recon-ranker` | 攻击面排序 | `bb-methodology` §Part 2 |
| `autopilot` | 狩猎循环 | 根据目标自动路由 |
| `validator` | 验证发现 | `triage-validation` |
| `chain-builder` | 危害升级 | 漏洞类权威 Skill §Chain |
| `report-writer` | 报告生成 | `report-writing` |

---

## 10. 互补 Skill 对（同时加载）

| 场景 | Skill Pair | 原因 |
|------|-----------|------|
| Web 漏洞猎杀 | 权威 Skill + `web2-vuln-classes` | 方法论 + 24 类参考 |
| 自动侦察 | `web2-recon` + `recon-and-methodology` | 工具执行 + 手动分析 |
| AI 安全 | `llm-prompt-injection` + `ai-ml-security` + `web2-vuln-classes` §LLM | 三层覆盖 |
| 认证测试 | `authbypass-authentication-flaws` + `jwt-oauth-token-attacks` + `oauth-oidc-misconfiguration` | Auth 全家桶 |
| 资产深度发现 | `web2-recon` + `permutation_gen.sh` + `csp_intel.sh` | 三维资产发现 |
| 关联资产测绘 | `recon-and-methodology` + `favicon_hunt.sh` + `asn_discovery.sh` | 网络+图标双维关联 |
| CDN/WAF绕过后探测 | `cdn_origin.sh` + `ssrf-server-side-request-forgery` | 源站直连+SSRF 组合 |
| 前端源码审计 | `js_sourcemap.sh` + `secrets_hunt.sh` | 源码还原→凭据提取 |
| 小程序+App双端 | `miniapp-recon` + `mobile-pentest` | 小程序+App API互补覆盖 |
| 实时资产监控 | `certstream_watch.sh` + `github_watch.sh` | 秒级新域名+预发布代码资产 |
| 报告 | `report-writing` + `triage-validation` | 写前验证 |

---

## 11. Anthropic 防御场景路由（全功能模式）

> 文件位置: `anthropic-skills/<skill-dir>/SKILL.md`

| 用户输入关键词 | 路由 Skill 目录 | 说明 |
|--------------|----------------|------|
| 取证/内存/磁盘/时间线/forensics | `anthropic-skills/digital-forensics-*` | 76+ 取证技能 |
| 恶意软件/样本/C2/沙箱/malware | `anthropic-skills/malware-analysis-*` | 100+ 样本分析 |
| 威胁情报/APT/IOC/TTPs/threat-intel | `anthropic-skills/threat-intelligence-*` | 80+ 情报技能 |
| SOC/告警/SIEM/SOAR/检测规则 | `anthropic-skills/soc-operations-*` | 96+ 检测技能 |
| 钓鱼/社工/BEC/phishing | `anthropic-skills/phishing-*` | 20+ 社工技能 |
| 勒索软件/ransomware/加密/支付 | `anthropic-skills/ransomware-*` | 15+ 勒索技能 |
| 云安全/AWS/Azure/GCP/K8s/CloudTrail | `anthropic-skills/cloud-security-*` | 30+ 云技能 |
| 合规/NIST/CMMC/ISO/PCI/compliance | `anthropic-skills/compliance-*` | 12+ 合规技能 |
| 应急响应/IR/incident/事件响应 | `anthropic-skills/incident-response-*` | 50+ IR技能 |
| 漏洞管理/CVE/CVSS/patch/补丁 | `anthropic-skills/vulnerability-management-*` | 20+ 漏管技能 |
| 供应链/SBOM/依赖/supply-chain | `anthropic-skills/supply-chain-*` | 10+ 供链技能 |
| AI安全/LLM防御/ATLAS/AI RMF | `anthropic-skills/ai-security-*` | ATLAS+AI RMF+F3 |

**使用方式**: 遇到上述关键词时，读取对应 Skill 目录下的 `SKILL.md`，不要从记忆中回答防御流程。

---

## 12. src-hunter H1案例查询路由

> 文件位置: `references/h1-reports/by-weakness/<vuln-type>/*.json`

| 漏洞类型 | 案例路径 | 说明 |
|---------|---------|------|
| XSS | `references/h1-reports/by-weakness/xss/` | 存储型/反射型/DOM实战案例 |
| SQLi | `references/h1-reports/by-weakness/sqli/` | Blind/时间盲/OOB案例 |
| SSRF | `references/h1-reports/by-weakness/ssrf/` | 内网探测/RCE升级案例 |
| IDOR | `references/h1-reports/by-weakness/idor/` | 越权读/越权写实战案例 |
| RCE | `references/h1-reports/by-weakness/rce/` | 命令注入/反序列化RCE案例 |
| File Upload | `references/h1-reports/by-weakness/file-upload/` | Bypass+Shell案例 |
| Auth Bypass | `references/h1-reports/by-weakness/auth-bypass/` | JWT/OAuth/SAML绕过案例 |
| 业务逻辑 | `references/h1-reports/by-weakness/business-logic/` | 竞态/支付/逻辑绕过案例 |

**强制规则**: 报告中引用案例时必须 Read 对应 JSON 文件，不得凭记忆引用案例编号。

**扩展案例库**（§12 主表外的额外参考）：
| 来源 | 路径 | 说明 |
|------|------|------|
| H1 TOP100 报告（按漏洞类型） | `references/hackerone-reports-bug-bounty/tops_by_bug_type/` | XSS/SQLi/SSRF/IDOR/RCE 等20类历年TOP报告 |
| H1 TOP100 报告（按程序） | `references/hackerone-reports-bug-bounty/tops_by_program/` | Shopify/GitLab/PayPal/Uber 等50+程序高奖金报告 |
| H1 精选汇总 | `references/hackerone-reports-bug-bounty/tops_100/` | 全局TOP100付费/赞数排行 |
| Payload 分类库 | `references/payloader/by-category/web/` | 25类Web漏洞（XSS/SQLi/SSRF/RCE/业务逻辑/...） |
| Payload 内网库 | `references/payloader/by-category/intranet/` | 域渗透/横向/提权/隧道/免杀12类 |
| Payload 工具索引 | `references/payloader/tools/` | 红队/信息收集/内网/密码/漏洞利用等工具清单 |

---

## 13. Validator 验证层 + Oracle 确定性验证

> 工具位置: `aimy/tools/validator.py` | `tools/verification_oracle.py`
> 集成到: `record_finding()` 自动调用 + `triage-validation` Gate 0

| 验证级别 | 漏洞类 | 方法 |
|---------|--------|------|
| ✅ 代码级 | SSRF/SQLi/XSS/XXE/SSTI/CMDi/LFI | OOB回调/Playwright/时间差/布尔盲注 |
| ✅ 代码级 | IDOR/CORS/GraphQL/JWT | 跨会话对比/Origin反射/内省查询 |
| 🟡 半自动 | Race/Smuggling/CRLF/Cache/Prototype | 并行请求+人工确认 |

**集成验证 Oracle**:

| 场景 | 接入方式 | 判断标准 |
|------|---------|---------|
| SQLi Boolean确认 | `verification_oracle.verify_boolean(url, param, true_payload, false_payload)` | 响应差异 >10% |
| SQLi 时间确认 | `verification_oracle.verify_time(url, param, sleep_payload, baseline)` | 延迟差 ≥sleep秒×0.8 |
| XSS存储确认 | `verification_oracle.verify_stored_xss(target, trigger_url)` | OOB callback 触发 |
| SSRF确认 | `oob_server.wait_callback(payload_id, timeout=10)` | DNS/HTTP OOB命中 |
| IDOR确认 | `deviation_oracle.compare(resp_a, resp_b)` | 关键字段差异 |

**规则**: `confirmed` → 自动进飞轮；`rejected` → 不进飞轮、不污染FeedbackDB；`downgraded` → 降级进
**使用时机**: 工具报告漏洞 → 先调 verification_oracle 确认 → 再输出结论

> 配套技能: `skills/triage-validation/skill.md`（7问门 + 4验收门完整版）
> 去重工具: `aimy/tools/dedup.py` | 幻觉检测: `aimy/tools/canary.py`

---

## 14. 外部融合技能（四源之外的新增补充）

> 来源: [elementalsouls/Claude-BugHunter] + [shaniidev/bug-reaper]
> 2026-06-30 融合注入 EVX 飞轮，参与优胜劣汰

### P0 — 核心新增
| 技能 | 来源 | 用途 | 优先级 |
|------|------|------|--------|
| `evidence-hygiene` | CBH | PoC截图/脱敏/HAR清理/Burp截图规范 — 写报告前必读 | 🔴 每次提交前 |
| `m365-entra-attack` | CBH | M365/Entra ID攻击链: AADSTS码/ROPC spray/CA绕过 | 🟠 企业目标 |
| `okta-attack` | CBH | Okta SSO: 租户枚举/MFA绕过/SP配置滥用 | 🟠 企业目标 |
| `cloud-iam-deep` | CBH | AWS/Azure/GCP IAM信任策略滥用/角色链攻击 | 🟠 云目标 |
| `hunt-dispatch` | CBH | 漏洞发现调度器 — 按概率排序测试路径 | 🟢 狩猎效率 |

### P1 — 专项补充
| 技能 | 来源 | 用途 |
|------|------|------|
| `vmware-vcenter-attack` | CBH | vCenter渗透方法论 |
| `enterprise-vpn-attack` | CBH | Pulse/Citrix/FortiGate VPN攻击 |
| `supply-chain-attack-recon` | CBH | NPM/PyPI/GitHub Actions供应链攻击面 |
| `offensive-osint` | CBH | OSINT方法论 (1703行) |
| `redteam-mindset` | CBH | 红队思维框架 |
| `bb-local-toolkit` | CBH | 本地工具链整合 |
| `bugcrowd-reporting` | CBH | Bugcrowd专用报告模板 |

### P2 — 参考引用
| 文件 | 来源 | 用途 |
|------|------|------|
| `references/chaining.md` | bug-reaper | 8条P3→P1链式升级路线图 |
| `references/source-code-audit.md` | bug-reaper | 白盒审计方法论 |
| `references/waf-bypass.md` | bug-reaper | WAF绕过结构化指南 |
| `references/exploit-validation.md` | bug-reaper | 输入→控制点→接收器追踪法 |
| `references/ATTACK_COVERAGE.md` | 彦 | 攻击覆盖矩阵（55KB）— 所有漏洞类型的覆盖程度评估 |

**飞轮注入**: `python -m aimy.memory.external_sync --inject`（脚本: `aimy/memory/external_sync.py`）将外部技法注入 FeedbackDB，与真实挖洞产出同台竞技
**GitHub同步**: `python -m aimy.memory.github_sync`（脚本: `aimy/memory/github_sync.py`）

---

## 15. 合规报告输出路由

> 映射文件位置: `mappings/mitre-attack/` | `mappings/nist-csf/` | `mappings/owasp/`

| 报告类型 | 需附加内容 | 文件来源 |
|---------|-----------|---------|
| H1/Bugcrowd报告 | CVSS评分 + CWE编号 | `references/templates/h1-report-template.md` |
| 企业渗透测试报告 | MITRE ATT&CK TTP | `mappings/mitre-attack/enterprise-attack.json` |
| 合规差距评估 | NIST CSF 控制项 | `mappings/nist-csf/` |
| OWASP风险报告 | OWASP Top10 映射 | `mappings/owasp/` |
| 赏金报告 | impact评级 + PoC + 修复建议 | `report-writing` Skill |
| 红队报告 | 攻击链 + TTP + 行动总结 | `skills/redteam-report-template/SKILL.md` |

**强制**: 输出最终报告前读取对应模板文件，不得从记忆生成报告格式。

---

## 16. CBB 独有 Skill 触发场景

这些是 CBB 贡献的新能力，无原始 Skill 对应，直接加载：

| Skill | 触发场景 | 说明 |
|-------|---------|------|
| `bb-methodology` | 开始任何 SRC 会话 | 5 阶段思维框架 + 决策流 |
| `bug-bounty` | 需要工具编排 | 完整管线索引 + shell 命令 |
| `web2-recon` | 自动侦察 | subfinder/httpx/katana 管线 |
| `cicd-security` | CI/CD 安全 | GitHub Actions 注入/供应链 |
| `credential-attack` | 密码攻击 | 喷洒方法论 + go/no-go 门 |
| `meme-coin-audit` | Meme 币审计 | Rug pull 检测 + 8 类 token bug |
| `mobile-pentest` | 移动 App 测试 | APK/IPA → 流量拦截 → API 测试 |
| `report-writing` | 报告撰写 | H1/Bugcrowd/Intigriti/Immunefi 模板 |
| `triage-validation` | 验证发现 | 7 问门 + 4 验收门 |
| `security-arsenal` | 速查表 | 方法论速查 + 参考链接 |
| `miniapp-recon` | 小程序资产发现 | 微信/支付宝/抖音 AppID→API端点→云资源 |

---

## 17. 工具执行层映射

| 命令 | 脚本入口 | Skill 上下文 |
|------|---------|-------------|
| `/recon` | `tools/recon_engine.sh` | `web2-recon` |
| `/hunt` | `tools/hunt.py` | `bug-bounty` + 漏洞类权威 Skill |
| `/autopilot` | Agent `autopilot` | `bb-methodology` |
| `/validate` | `tools/validate.py` | `triage-validation` |
| `/report` | Agent `report-writer` | `report-writing` |
| `/bypass-403` | `tools/bypass_403.sh` | `401-403-bypass-techniques` |
| `/scan-cves` | `tools/cve_scan.sh` | — (自动) |
| `/cloud-recon` | `tools/cloud_recon.sh` | `web2-recon` |
| `/param-discover` | `tools/param_discovery.sh` | `api-recon-and-docs` |
| `/web3-audit` | Agent `web3-auditor` | `smart-contract-vulnerabilities` |
| `/token-scan` | `tools/token_scanner.py` | `meme-coin-audit` |
| `/spray` | `tools/spray_orchestrator.sh` | `credential-attack` |
| `/secrets-hunt` | `tools/secrets_hunter.sh` | `web2-recon` |
| `/takeover` | `tools/takeover_scanner.sh` | `subdomain-takeover` |
| `/graphql-audit` | `tools/graphql_audit.sh` | `graphql-audit` |
| `/asn-discovery` | `tools/asn_discovery.sh` | `recon-and-methodology` |
| `/permutation-gen` | `tools/permutation_gen.sh` | `web2-recon` |
| `/favicon-hunt` | `tools/favicon_hunt.sh` | `recon-and-methodology` |
| `/cdn-origin` | `tools/cdn_origin.sh` | `cloud-recon` |
| `/js-sourcemap` | `tools/js_sourcemap.sh` | `web2-recon` |
| `/csp-intel` | `tools/csp_intel.sh` | `recon-and-methodology` |
| `/mass-inject` | `aimy/tools/mass_inject.py` | 批量注入检测 |
| `/dedup` | `aimy/tools/dedup.py` | 发现去重 |
| `/canary` | `aimy/tools/canary.py` | 金丝雀/幻觉检测 |
| `/chain-suggest` | `aimy/tools/chain_suggest.py` | 利用链建议 |
| `/intel` | `aimy/intel_query.py` | 威胁情报查询 |

---

## 18. 加载模式（Token 参考）

| 模式 | 触发条件 | 加载范围 | 估算Token |
|------|---------|---------|----------|
| **挖洞模式** | 挖洞/SRC/hunt/漏洞/渗透/CTF | `skills/` 101个攻击技能<br>`references/` H1案例+Payload<br>`tools/` Python工具 | ~30k |
| **全功能模式** | 取证/IR/SOC/合规/恶意软件/威胁情报/蓝队 | 以上 + `anthropic-skills/` 818个防御技能 | ~100k+ |

**规则**：
- 默认进入**挖洞模式**，不加载 `anthropic-skills/`
- 只有明确出现防御/取证/合规关键词时，才切换全功能模式
- 挖洞过程中遇到需要防御知识时，**单独按需加载**对应技能，不加载全部
