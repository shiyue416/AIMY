# AIMY v3.0 — AI 漏洞赏金猎手框架

<p align="center">
  <strong>七维资产收集 &middot; 180 攻击技能 &middot; 120+ Python 检测器 &middot; 3,000+ H1 报告</strong><br>
  四源融合 — HackSkills · Anthropic · src-hunter · 洺熙注入<br>
  <sub>七阶段挖洞管线 · 35 触发词自动加载 · 21 Go 工具 + 2 企业工具</sub>
</p>

---

## 从头安装（5 分钟）

```bash
# 1. 克隆
git clone https://github.com/shiyue416/AIMY.git && cd AIMY

# 2. Python + LLM
pip install -r aimy/requirements.txt
cp .env.example .env          # 编辑，至少填入一个 LLM API Key

# 3. 一键安装全部工具链
bash tools/setup-tools.sh      # 21 Go + Python + gf 模式 + Shell 管线 + OneForAll
```

**enscan 需手动下载**（18MB，不在 git 内）：

```bash
# 从 https://github.com/wgpsec/ENScan_GO/releases 下载
# 解压 enscan.exe + config.yaml → ~/go/bin/
```

**验证**：

```bash
python aimy.py --list-providers   # LLM 连通
bash tools/setup-tools.sh         # 应该全部 ✅
```

---

## 开始挖洞（3 条路径）

### 路径 A: Shell 管线 — 资产收集

```bash
bash ~/.claude/tools/recon_engine.sh target.com                        # 标准侦察
bash ~/.claude/tools/full_recon.sh target.com "公司名"                  # 全量（含企业关联）
bash ~/.claude/tools/enscan_recon.sh "公司名" target.com                # 仅企业扩展
bash ~/.claude/tools/favicon_hunt.sh --url https://target.com           # 图标关联
bash ~/.claude/tools/js_sourcemap.sh recon/target.com                   # JS 源码还原
```

### 路径 B: Python CLI — 漏洞挖掘

```bash
python aimy.py                                    # 交互模式
python aimy.py --target target.com                # 全自动（侦察→挖洞→报告）
python aimy.py -q "hunt example.com 挖 ssrf"      # 一句话
```

### 路径 C: 对话命令 — AI 驱动

```
/recon target.com               # Phase 2 侦察
/hunt target.com                # Phase 3+4 挖洞
/hunt target.com --vuln-class ssrf
/validate                       # Phase 5 验证门
/report bounty                  # Phase 6 生成报告
```

---

## 资产收集七维法

Shell 管线自动执行，默认**零发包**（仅第三方 API）。

| 维度 | 工具 | 效果 |
|------|------|------|
| ① 子域名被动 | crt.sh · Chaos · subfinder · amass · assetfinder · **OneForAll** | 覆盖率 90-95% |
| ② 企业关联 | **enscan** → ICP 备案 · 分支机构 · 股权穿透 · 供应商 | 企业名→域名反向发现 |
| ③ 排列变异 | dnsgen · alterx | 1→50 倍放大 |
| ④ 图标关联 | mmh3 hash → FOFA · Shodan | 跨资产发现 |
| ⑤ ASN/IP 反查 | asnmap · amass intel · bgp.he.net | 网络级关联 |
| ⑥ CSP 情报 | CSP 响应头解析 → httpx | 免费子域名 |
| ⑦ JS 源码还原 | katana · gau · waybackurls · .js.map → TypeScript | 端点+凭据 |

```
┌─ 被动层 (零发包):  crt.sh + CSP + favicon + GitHub dorking
├─ 枚举层 (主动):    subfinder + amass + OneForAll + permutation_gen
├─ 企业层 (工商):    enscan (ICP+分支+股权+供应商) → 域名反向发现
├─ 验证层:           dnsx + httpx + cdn_origin
├─ 扩展层:           katana + gau + js_sourcemap
└─ 关联层:           asn_discovery + favicon_hunt + csp_intel
```

---

## 七阶段挖洞管线

```
Phase 1  Intake     接单 — scope 校验、规则加载、时间盒设定
Phase 2  Recon      侦察 — 七维被动（零发包）
Phase 3  Enum       枚举 — 主动探测（≤1 req/s）
Phase 4  Hunt       狩猎 — 信号→playbook→工具 三级调度
Phase 5  Validate   验证 — 8 问门 + 4 验收关
Phase 6  Report     报告 — 模板驱动，PII 脱敏
Phase 7  Flywheel   飞轮 — 技法入库，战报刷新
```

---

## Skill 自动加载（35 类漏洞，禁止凭记忆生成 payload）

| 触发词 | 自动加载 |
|--------|---------|
| SSRF / url= / webhook / proxy / callback | `ssrf-server-side-request-forgery` |
| SQLi / id= / 注入 / union / select / sleep | `sqli-sql-injection` |
| XSS / q= / search / innerHTML / DOM | `xss-cross-site-scripting` |
| IDOR / /api/user/ / 越权 / uuid / BOLA | `idor-broken-object-authorization` |
| CMDi / cmd= / exec / shell / ping | `cmdi-command-injection` |
| SSTI / template / {{ / {% / render / jinja | `ssti-server-side-template-injection` |
| JWT / Bearer / eyJ / token / alg / kid | `jwt-oauth-token-attacks` |
| LFI / file= / path= / ../ / 目录遍历 | `path-traversal-lfi` |
| XXE / xml / <!DOCTYPE / svg | `xxe-xml-external-entity` |
| 403 / 401 / forbidden / access denied | `401-403-bypass-techniques` |
| 业务逻辑 / 支付 / 价格 / coupon / 订单 | `business-logic-vulnerabilities` |
| Race / 竞态 / TOCTOU | `race-condition` |
| CORS / Access-Control / 跨域 | `cors-cross-origin-misconfiguration` |
| GraphQL / graphql / introspection | `graphql-audit` |
| HTTP Smuggling / CL.TE / TE.CL / desync | `request-smuggling` |
| Prototype Pollution / __proto__ | `prototype-pollution` |
| WAF / cloudflare / akamai / blocked | `waf-bypass-techniques` |
| OAuth / OIDC / redirect_uri / PKCE | `oauth-oidc-misconfiguration` |
| LLM / AI / prompt injection / chatbot | `llm-prompt-injection` |
| ... | 15 更多（见 CLAUDE.md 完整表） |

---

## 专项 Agent

| Agent | 专攻 |
|-------|------|
| `ssrf-hunter` | SSRF — OOB + interactsh + 绕过 |
| `sqli-hunter` | SQLi — 布尔/时间/报错/OOB |
| `xss-hunter` | XSS — 反射/存储/DOM |
| `idor-hunter` | IDOR/BOLA — 对象级越权 |
| `rce-hunter` | RCE — SSTI/反序列化/CMDi/XXE |
| `validator` | 确定性验证 — curl + 8 问门 |

---

## 运行模式

```bash
AIMY_MODE=veteran    # 老鸟（默认）— 过滤低危，输出简洁
AIMY_MODE=rookie     # 菜鸟 — 完整输出 + 修复建议

AIMY_SCENE=bounty       # 赏金（默认）— 只读，证明即停
AIMY_SCENE=pentest      # 渗透 — 后利用链，横向移动
AIMY_SCENE=redteam      # 红队 — 隐蔽优先，持久化
AIMY_SCENE=auto-pentest # 全自动渗透 — 无人介入
```

---

## 安全铁规

| 约束 | 数值 |
|------|------|
| 速率 | ≤1 req/s，≤500 次/天，并发 ≤5 |
| 数据 | ≤3 条用户数据，发现即停 |
| 写入 | 只读优先（`id`/`whoami`/`uname -a`） |
| 断路器 | 连续错误 >10 → 自动停 5 分钟 |
| Scope | 只测授权域名，发包前必须确认 |
| 禁止 | DoS · 改数据 · 扫内网 · 绕 MFA · 绕验证码 · 暴破真实用户 · 公共 DNSLog · 供应链投毒 |
| 合规 | CFAA · 网络安全法 · API Key 只用环境变量，绝不硬编码 |

---

## 工具链总览

| 类别 | 数量 | 工具 |
|------|:----:|------|
| Go 工具 | 21 | subfinder · amass · assetfinder · httpx · dnsx · naabu · nuclei · katana · gau · waybackurls · hakrawler · ffuf · interactsh-client · dalfox · alterx · anew · asnmap · gf · getJS · trufflehog · uncover |
| Python 工具 | 2 | bbot · FOFA-py |
| 企业工具 | 2 | enscan (企业侦察) · OneForAll (全量子域名) |
| Shell 管线 | 10 | recon_engine · full_recon · enscan_recon · favicon_hunt · asn_discovery · csp_intel · js_sourcemap · cdn_origin · safety_precheck · setup-tools |
| Python 检测器 | 120+ | ssrf · sqli · xss · cmdi · ssti · jwt · lfi · idor · race · cors · graphql · deser · proto_pollution … |

---

## 架构

```
AIMY/
├── aimy/                    Python 框架 (261 .py)
│   ├── core/                调度器 · ReAct 循环 · 状态机
│   ├── tools/               120+ 漏洞检测器 · 安全门禁
│   ├── memory/              飞轮引擎 · 战报 · H1 同步
│   └── llm/                 多模型客户端
├── skills/                  180 攻击方法论技能
├── anthropic-skills/        8,946 防御/取证/合规技能
├── references/              5,891 参考文件 (H1报告 3,029 + Payload 52 + Playbook 68)
├── tools/                   10 Shell 管线脚本
├── wooyun_public/           51,964 WooYun 案例
└── 彦的h1飞轮/               116 类技法 + 32 资源库
```

---

## 文档

| 文件 | 内容 |
|------|------|
| [README.md](./README.md) | 本文件 |
| [QUICKSTART.md](./QUICKSTART.md) | 从零安装 + 命令速查 + 排错 |
| [DISCLAIMER.md](./DISCLAIMER.md) | 免责声明 + 授权范围 + 操作红线 |
| [CLAUDE.md](./CLAUDE.md) | Agent 身份定义 · 技术栈 · 完整触发词表 |
| [SKILL.md](./SKILL.md) | Fusion-router 调度中枢 |
| [INDEX.md](./INDEX.md) | 完整技能索引 |

---

## 免责声明

> 完整条款见 [DISCLAIMER.md](./DISCLAIMER.md)。**工具仅用于授权安全测试。你对你使用本工具的所有行为负全部责任。"AI 做的"不构成法律辩护理由。**
>
> 部分 SRC 平台（360SRC 等）明文规定：纯 AI 报告直接驳回，累计 ≥5 条拉黑账号。所有发现必须经过人工验证。

MIT License — 各 Skill 文件见各自许可证。
