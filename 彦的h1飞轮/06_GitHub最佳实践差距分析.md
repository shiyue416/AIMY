# 🧬 GitHub 顶级项目差距注入 — 飞轮进化指令

> 来源: H-mmer/pentest-agents · elementalsouls/Claude-BugHunter · transilienceai/communitytools · src-hunter-skill · public-skills-builder
> 注入时间: 2026-07-01 · 更新时间: 2026-07-06
> 状态: 15 新技能 + 2,888 H1 报告 + 3 框架 + 1 管线 已融合 ✅

### ✅ 已闭合差距 (2026-07-01)

| # | 差距 | 修补方案 | 状态 |
|---|------|---------|:----:|
| 1 | 多智能体蜂群协同 | 9 agent (coordinator/idor/xss/ssrf/sqli/rce/biz/validator/report) | ✅ |
| 2 | 自动修复漏洞/风控 | remediation-agent + WAF/BCheck/nuclei/风控规则生成 | ✅ |
| 3 | 知识沉淀到智能体能力 | flywheel.py Step 5.5: FeedbackDB→agent 文件自动注入 | ✅ |
| 4 | 7×24 自动运营 | flywheel.py Step 1.5: 自检+自愈 agent | ✅ |
| 5 | 分钟级研判 | Validator + Canary OOB 已在 record_finding() 中 | ✅ |
| 6 | 自动修复/风控联动 | remediation-agent 输出 5 种阻断产物 | ✅ |

---

## 一、必须补的 3 个架构差距

### 🔴 P0: Agent 拆分（对标 pentest-agents 50 agents）

**现状**: fusion-router Phase 4 Hunt 是手动流程，一次加载全量 skill
**目标**: 每个漏洞类拆成独立 agent，实现并行狩猎

## 二、2026-07-06 外部项目融合成果

### ✅ 本次融合 (2026-07-06)

| 源 | 融合内容 | 增量 |
|---|---------|------|
| **elementalsouls/Claude-BugHunter** | 15 个新 skill（APK管线/ASP.NET/gRPC/Laravel/Next.js/Node.js/SharePoint/SpringBoot/MFA/NTLM/TLS/SOC感知/ATO/DOM/Session） | +15 skill |
| **src-hunter-skill (MyuriKanao)** | 2,888份H1报告(141类) + payloader + 字典 + playbooks | +2,888参考 |
| **public-skills-builder** | H1→Skill 自动蒸馏管线就绪 | +1 管线 |
| **transilienceai/communitytools** | 5 skill + 104/104 benchmark论文 | +5 skill |
| **H-mmer/pentest-agents** | 3 skill + 50 agent定义 + 2 MCP | +3 skill |

### 📊 技能矩阵更新 (180 total)

| 新能力 | 填补空白 | 场景 |
|-------|---------|------|
| gRPC 安全测试 | 完全新增 | 微服务架构 |
| ASP.NET 专精 | 完全新增 | .NET Webforms/WCF/SharePoint |
| Spring Boot 专精 | 完全新增 | Java Actuator/heapdump |
| Laravel/Next.js/Node.js | 框架级覆盖 | 现代 Web 框架 |
| APK 反向管线 | 移动端深度 | APK→JADX→Frida→API |
| MFA 7种绕过 | 完全新增 | 认证绕过 |
| NTLM 信息泄露 | 完全新增 | AD 侦察 |
| TLS 网络测试 | 完全新增 | 协议层 |
| SOC 感知 | 完全新增 | 红队场景 |
| ATO/DOM/Session | 完全新增 | 前端/认证 |
| 攻击路径拼接 | 完全新增 | 多跳攻击链 |
| 技术栈识别 | 完全新增 | OSINT |
| 源码审计 | 完全新增 | SAST |
| CVE PoC 生成 | 完全新增 | 自动化 |
| SAST 方法论 | 完全新增 | 代码审计流程 |
| 狩猎方法论 | 完全新增 | 整体狩猎流程 |

### 📦 pentest-agents Agent 目录 (参考)
50 agent 定义存储在 `aimy/references/pentest-agents/agents/`，可直接参考格式创建新的 agent。
2 个 MCP 服务器（bounty + writeup）代码在 `aimy/references/pentest-agents/`。

### 📄 104/104 CTF Benchmark 论文
`references/methodology/practice-makes-perfect.pdf` — transilienceai 方法论

需要创建的 agent：
```
recon               侦察
recon-ranker        资产排序
idor-hunter         IDOR
xss-hunter          XSS
ssrf-hunter         SSRF
sqli-hunter         SQL注入
rce-hunter          RCE/反序列化/SSTI
race-condition      条件竞争
business-logic      业务逻辑
graphql-audit       GraphQL
oauth-hunter        OAuth
cors-hunter         CORS
csrf-hunter         CSRF
file-upload         文件上传
chain-builder       利用链
poc-builder         证据生成
report-writer       报告
quality-check       质量门
```

**格式**: `.claude/agents/<name>.md`（pentest-agents 标准格式）

### 🔴 P1: 企业身份攻击矩阵（对标 Claude-BugHunter 5 skills）

**现状**: 你有 127 个攻击 skill 但没有企业身份专项
**需要新增**:
- `m365-entra-attack` — Entra ID 攻击链（AADSTS码/ROPC spray/CA绕过）
- `okta-attack` — Okta SSO 滥用（租户枚举/MFA绕过/SP配置）
- `vmware-vcenter-attack` — vCenter 渗透方法论
- `enterprise-vpn-attack` — Pulse/Citrix/FortiGate VPN 攻击
- `cloud-iam-deep` — AWS/Azure/GCP IAM 信任策略滥用

### 🟡 P2: 跨会话持久化 Brain（对标 pentest-agents brain）

**现状**: session_brief 是静态的，不跟踪"哪些端点已测"
**目标**: 扩展 `aimy/memory/session_brief.py` 加 `endpoint_tracking.json`
```
已测端点: {url, vuln_class, status, timestamp, result}
未测端点: {url, vuln_class, priority}
死胡同:  {url, reason, exhausted_at}
```

---

## 二、验证基准（对标 communitytools 104/104 CTF）

**目标**: 在 104 靶机上跑通 AIMY，量化真实水平

```bash
cd /c/Users/PC/Desktop/validation-benchmarks
# 逐个靶机跑
python aimy.py auto http://localhost:<port> --mode veteran
```

**已知差距**（transilienceai 论文指出）:
- 89.4% 是 baseline（纯 LLM）
- 104/104 需要约 15 轮迭代：失败→分析→补 skill→重跑
- 技能文件质量决定上限

---

## 三、技能文件剪枝（对标 communitytools 精简结构）

**现状**: 每个 skill 文件包含大量冗余
**目标**: 按 communitytools 模式精简——每个 skill 只保留：
1. 核心 payload（5-10 条足够）
2. 验证方法（curl/OOB/布尔）
3. 引用链接（不内联全部内容）

**优先级**: SSRF、SQLi、XSS 三个最常用 skill 先剪枝

---

## 四、跨 IDE 适配（远期）

**现状**: Claude Code only
**目标**: 适配 Codex/Gemini/Cursor/Windsurf

pentest-agents 的 provider 翻译器在 `tools/installer/`，可以复用其思路。

---

## 五、飞轮触发计划

```
本周:
  ├─ 创建 20 个 agent（P0）
  ├─ 导入企业身份 5 skill（P1）
  └─ 启动 104 靶机第一轮跑分

本月:
  ├─ Agent 并行化 → Phase 4 全自动
  ├─ Brain 持久化 → 跨会话端点跟踪
  └─ 104 靶机迭代至 95%+

下季:
  ├─ 跨 IDE 适配
  └─ 公开 benchmark 报告
```
