# AIMY v3.0 — AI 漏洞赏金猎手框架

<p align="center">
  <strong>七维资产收集 · 180 攻击技能 · 120+ 检测器 · 21 Go 工具 · 3,000+ H1 报告</strong><br>
  从安装到提交第一个漏洞，全流程指南<br>
</p>

---

## 目录

- [这个项目是干什么的](#这个项目是干什么的)
- [前置条件](#前置条件)
- [第一步：安装](#第一步安装)
- [第二步：配置](#第二步配置)
- [第三步：安装工具链](#第三步安装外部工具)
- [第四步：验证环境](#第四步验证环境)
- [第五步：开始挖洞](#第五步开始挖洞)
- [完整示例：挖一个真实目标](#完整示例挖一个真实目标)
- [深入：七阶段管线详解](#深入七阶段管线详解)
- [场景模式怎么选](#场景模式怎么选)
- [安全红线](#安全红线)
- [常见问题与排错](#常见问题与排错)
- [工具清单](#工具清单)
- [架构](#架构)
- [文档索引](#文档索引)

---

## 这个项目是干什么的

AIMY 是一个**漏洞赏金猎人（Bug Bounty Hunter）的工具箱**。它帮你做三件事：

1. **发现资产** — 目标公司有哪些域名？子域名？子公司？用了什么技术？
2. **挖掘漏洞** — 在这些资产上自动检测 SSRF、SQL 注入、XSS、越权等 35 类漏洞
3. **验证和报告** — 确认漏洞真实存在后，生成可以提交到 HackerOne、补天、360SRC 的报告

**你不写代码也能用。** 大部分操作是一条命令。

---

## 前置条件

这些东西需要提前装好：

| 你需要 | 是什么 | 怎么装 |
|--------|--------|--------|
| **Git** | 代码下载工具 | `winget install Git.Git` 或 [git-scm.com](https://git-scm.com) |
| **Go 1.21+** | Go 语言（用来编译安全工具） | `winget install GoLang.Go` 或 [go.dev](https://go.dev) |
| **Python 3.10+** | Python 语言（AI 框架跑在这上面） | `winget install Python.Python.3.12` 或 [python.org](https://python.org) |
| **一个 LLM API Key** | AI 大模型的调用权限 | 见下方配置章节 |

装完后打开终端（PowerShell 或 CMD），确认版本：

```bash
git --version     # 应输出 git version 2.xx
go version        # 应输出 go version go1.21+
python --version  # 应输出 Python 3.10+
```

---

## 第一步：安装

```bash
# 下载项目
git clone https://github.com/shiyue416/AIMY.git
cd AIMY

# 安装 Python 依赖
pip install -r aimy/requirements.txt
```

> **pip 是什么？** Python 的包管理器。这条命令会自动下载 AIMY 需要的所有 Python 库。

---

## 第二步：配置

```bash
# 复制配置模板
cp .env.example .env
```

用记事本或 VS Code 打开 `.env` 文件，填入 API Key。**至少填一个**，填哪个用哪个：

```ini
# === 任选一个填即可 ===
ANTHROPIC_API_KEY=sk-ant-xxx     # Claude (Anthropic)
OPENAI_API_KEY=sk-xxx            # GPT-5.5 / GPT-4 (OpenAI)
LONGCAT_API_KEY=ak_xxx           # 龙猫-2.0 (美团, 国内无需翻墙)
DEEPSEEK_API_KEY=sk-xxx          # DeepSeek (便宜, 挖洞够用)
GROQ_API_KEY=gsk_xxx             # Groq (免费额度, 速度极快)
GEMINI_API_KEY=AIza-xxx          # Gemini (Google)
XAI_API_KEY=xai-xxx              # Grok (xAI)
OPENROUTER_API_KEY=sk-or-xxx     # OpenRouter (聚合上百模型)
MOONSHOT_API_KEY=sk-xxx          # Kimi (月之暗面)
MISTRAL_API_KEY=xxx              # Mistral
TOGETHER_API_KEY=xxx             # Together AI
CEREBRAS_API_KEY=xxx             # Cerebras (极速推理)
PERPLEXITY_API_KEY=pplx-xxx      # Perplexity

# === 可选 — HackerOne 同步 ===
H1_USERNAME=你的H1用户名
H1_TOKEN=你的H1_Token
```

> **什么是 API Key？** 就是一串密钥，让 AIMY 能调用 AI 大模型来分析和挖洞。去对应的 AI 平台注册就能拿到，通常几十块钱能用一个月。
>
> **国内用户推荐龙猫**，不需要翻墙，注册地址搜"美团龙猫 LongCat"。

---

## 第三步：安装外部工具

AIMY 依赖 21 个开源安全工具来做资产收集和漏洞扫描。**一条命令全装好**：

```bash
bash tools/setup-tools.sh
```

这一步会安装：

| 类别 | 数量 | 内容 |
|------|:----:|------|
| Go 安全工具 | 21 个 | subfinder、amass、nuclei、httpx、katana…（自动 `go install`） |
| Python 工具 | 3 个 | sqlmap、arjun、bbot（自动 `pip install`） |
| gf 模式 | 1 套 | URL 自动分类规则 |
| OneForAll | 1 个 | 全量子域名收集（自动 `git clone`） |
| Shell 管线 | 9 个脚本 | 部署到 `~/.claude/tools/` |

> **需要多久？** 第一次安装大约 5-10 分钟（Go 编译需要时间）。以后更新只需要 `git pull`。

### 手动安装 enscan

enscan 是一个 18MB 的 Windows 可执行文件，没放在 git 里。需要手动下载：

```bash
# 1. 打开浏览器 → https://github.com/wgpsec/ENScan_GO/releases
# 2. 下载最新版 enscan-windows-amd64.zip
# 3. 解压，把 enscan.exe 和 config.yaml 放到:
#    C:\Users\你的用户名\go\bin\
```

> **enscan 是干什么的？** 输入一个公司名（比如"小米"），自动查出它旗下的子公司、分支机构、ICP 备案域名。用来从公司名反向发现隐藏资产。

---

## 第四步：验证环境

跑一遍验证，确保所有东西都装好了：

```bash
# 1. 验证 LLM 连通
python aimy.py --list-providers
# 应输出: 已配置的 AI 提供商列表

# 2. 验证 Go 工具链
bash tools/setup-tools.sh
# 所有工具应该显示 ✅。如果有 ❌，按提示手动安装。
```

---

## 第五步：开始挖洞

AIMY 提供**三条使用路径**，从简单到高级。

### 🟢 路径 A：Shell 管线（最简单，零门槛）

直接在终端敲命令，自动收集目标资产：

```bash
# 标准侦察 — 收集子域名、验证存活
bash ~/.claude/tools/recon_engine.sh target.com

# 全量侦察 — 上面 + 企业关联 + 子公司域名 + 图标关联 + CSP + JS
bash ~/.claude/tools/full_recon.sh target.com "公司名"
```

**跑完你会得到**：`recon/target.com/` 目录，里面有：

```
subs.txt          ← 发现的所有子域名
resolved.txt      ← DNS 解析通过的
live.txt          ← HTTP 存活的（带状态码和网页标题）
urls.txt          ← 爬到的所有 URL
ssrf.txt          ← 可疑的 SSRF 参数（自动分类）
sqli.txt          ← 可疑的 SQL 注入参数
xss.txt           ← 可疑的 XSS 参数
```

### 🟡 路径 B：Python CLI（一行命令全自动）

```bash
# 全自动 — 侦察 → 挖洞 → 验证 → 报告，一条龙
python aimy.py --target target.com

# 交互模式 — 敲命令逐步来
python aimy.py

# 一句话模式 — 快速提问
python aimy.py -q "hunt example.com 挖 ssrf"
```

### 🔴 路径 C：AI 对话（最强大，需要 Claude Code）

如果你在用 Claude Code（或任何支持 `/` 命令的 AI 编程助手），直接用自然语言：

```
/recon target.com                           # 开始侦察
/hunt target.com                            # 开始挖洞
/hunt target.com --vuln-class ssrf          # 只挖 SSRF
/hunt target.com --vuln-class sqli          # 只挖 SQL 注入
/hunt target.com --autonomous               # 全自动全覆盖 35 类漏洞
/validate                                   # 验证发现的漏洞
/report bounty                              # 生成赏金平台格式报告
```

---

## 完整示例：挖一个真实目标

假设你的目标是 `example.com`，母公司叫"示例公司"。

### Step 1：收集资产（2 分钟）

```bash
bash ~/.claude/tools/full_recon.sh example.com "示例公司"
```

输出大概是：

```
[+] Target: example.com
    crt.sh: 156 子域名
    subfinder: 89 子域名
    OneForAll: 203 子域名
[+] Total unique: 312

enscan:
    ICP 备案: 12 个域名
    分支机构: 3 家
    控股子公司: 5 家

[OK] 合并后总计: 347 唯一域名
    DNS 验证通过: 203
    HTTP 存活: 87
```

### Step 2：看看有哪些 URL（30 秒）

```bash
cd recon/example.com
cat live.txt | head -20
```

你会看到存活网站的列表，每行格式：`URL [状态码] [网页标题] [技术栈]`

### Step 3：用 Nuclei 扫一遍已知漏洞（3 分钟）

```bash
cat resolved.txt | ~/go/bin/nuclei -t ~/nuclei-templates/ -rate-limit 1 -concurrency 5
```

> **Nuclei 是什么？** 一个模板化的漏洞扫描器。它内置了上千个 CVE（公开漏洞）的检测模板，一键扫描目标是否存在已知漏洞。

### Step 4：对可疑参数深挖

打开 `sqli.txt`，里面是所有带 `?id=` `?user=` 之类参数的 URL。选一个跑 SQL 注入检测：

```bash
python aimy.py -q "检测这个 URL 有没有 SQL 注入: https://example.com/api/user?id=123"
```

### Step 5：验证 + 报告

如果 AI 说发现了漏洞，先验证：

```bash
/validate
```

验证通过后生成报告：

```bash
/report bounty
```

---

## 深入：七阶段管线详解

AIMY 把挖洞拆成 7 个阶段，每个阶段有明确的输入输出。

### Phase 1：接单（5 分钟）

**你要做**：确认你要测的目标在不在授权范围。不要测你没拿到授权的网站。

### Phase 2：侦察（2-10 分钟，零发包）

**AIMY 帮你做**：从第三方平台收集目标的所有资产。**这个阶段不会向目标发任何请求。**

七维覆盖：

| 维度 | 干什么 | 用的工具 |
|------|--------|---------|
| ① 子域名被动 | 从证书透明度日志、DNS 数据集收集子域名 | crt.sh · Chaos · subfinder · amass · **OneForAll** |
| ② 企业关联 | 从工商数据反查子公司和关联域名 | **enscan** → ICP 备案 · 分支机构 · 股权穿透 · 供应商 |
| ③ 排列变异 | 用已知子域名模式推测可能存在的其他子域名 | dnsgen · alterx |
| ④ 图标关联 | 通过网站图标的哈希值在 FOFA/Shodan 反查同源网站 | mmh3 hash → FOFA · Shodan |
| ⑤ ASN/IP | 从 IP 段反查属于该组织的所有域名 | asnmap · amass intel · bgp.he.net |
| ⑥ CSP 情报 | 解析目标网站的 CSP 安全头，提取里面列出的可信域名 | CSP 头解析 → httpx |
| ⑦ JS 源码 | 下载 JS 的 source map，还原 TypeScript 源码，提取 API 端点和密钥 | katana · gau · .js.map → source-map-unpack |

### Phase 3：枚举（5-15 分钟，首次发包）

**AIMY 帮你做**：验证哪些资产真的存活，开放了哪些端口，用了什么技术栈。**这个阶段开始向目标发包，但速度极慢（1 次/秒）。**

```bash
# dnsx 验证 DNS 是否解析
# httpx 验证 HTTP 是否存活，同时识别技术栈
# naabu 扫描常见端口
```

### Phase 4：狩猎（主要耗时）

**AIMY 帮你做**：对每个可疑的 URL 参数，用对应的漏洞检测器逐个测试。35 类漏洞，每类有专门的检测逻辑。

比如发现 URL 里有 `?url=https://xxx`：
1. 信号匹配 → `url=` 触发 SSRF 类别
2. 自动加载 `skills/ssrf-server-side-request-forgery/SKILL.md`
3. 按 Skill 里的 payload 逐个测试
4. 有回调 → 记录发现

### Phase 5：验证（每发现一个漏洞）

**8 问门**，必须全部通过才继续：

| # | 问题 | 不通过 |
|---|------|--------|
| Q1 | 攻击者能一步步复现吗？ | 否决 |
| Q2 | 影响在赏金平台接受列表里吗？ | 否决 |
| Q3 | 根本原因在授权资产上吗？ | 否决 |
| Q4 | 需要攻击者拿不到的特殊权限吗？ | 否决 |
| Q5 | 这已经是已知/接受的行为了吗？ | 否决 |
| Q6 | 能证明实际业务影响吗？ | 降级 |
| Q7 | 在禁止提交清单里吗（反射XSS/开放重定向/缺失安全头…） | 否决 |
| Q8 | 换个浏览器/session 还能复现吗？ | 否决 |

### Phase 6：报告

自动生成包含以下内容的报告：
- 漏洞标题（符合 HackerOne 格式）
- 复现步骤（curl 命令可直接复制）
- HTTP 请求/响应证据
- 业务影响描述
- CVSS 4.0 评分

**提交前必须人工复现一次。** 纯 AI 报告会被驳回，部分平台（360SRC）累计 ≥5 条直接拉黑。

### Phase 7：飞轮

每次挖洞的发现自动记录到本地技法库，下次挖洞 AI 自动参考高命中率技法。

**从本体拉取技法**（单向，你的数据不上传）：

```bash
aimy feedback pull                # 拉取最新的共享技法
python -m aimy.memory.session_brief  # 查看融合后的排行榜
```

> 只拉取技法名称和漏洞类型。你的本地数据（目标、漏洞细节、PII）**永远不离开你的机器**。

---

## 场景模式怎么选

```bash
# 设置场景（在运行前设置环境变量）
# Windows PowerShell:
$env:AIMY_SCENE="bounty"

# Linux/macOS:
export AIMY_SCENE=bounty
```

| 场景 | 适用情况 | 特点 |
|------|---------|------|
| `bounty`（默认） | 挖 SRC/HackerOne 赚赏金 | 只读，证明即停，自动过滤低危 |
| `pentest` | 客户给了你渗透测试授权 | 可以写文件、提权、横向移动 |
| `redteam` | 红蓝对抗 | 隐蔽优先、持久化、C2 |
| `auto-pentest` | 全自动渗透 | 无人介入，28 分钟跑完一个目标 |

另有**老鸟/菜鸟**子模式：

```bash
export AIMY_MODE=veteran   # 老鸟 — 只显示高价值漏洞，自动跳过反射XSS、信息泄露
export AIMY_MODE=rookie    # 菜鸟 — 显示所有发现 + 详细修复建议
```

---

## 安全红线

> **以下规则是硬约束。违反立即停止，没有例外。**

### 速率控制

| 规则 | 值 |
|------|-----|
| 每秒请求数 | ≤ 1 |
| 每天请求数 | ≤ 500 |
| 最大并发 | 5 |
| 连续错误 > 10 次 | 自动停 5 分钟 |
| 遇到 429（限流） | 停 5 分钟 |
| 遇到 503（服务不可用） | 停 10 分钟 |

### 数据安全

| 规则 | 限额 |
|------|------|
| SQL 注入 | 查到库名/版本即停，**不 dump 数据** |
| 越权/IDOR | 取 1-3 条样本即停 |
| RCE | 只跑 `id`/`whoami`/`uname -a`，**不写文件** |
| 文件读取 | 读到 `root:x:` 即停，**不读 /etc/shadow** |
| 发现数据泄露 | **立刻停止**，绝不扩大 |
| PoC 中的隐私数据 | 必须脱敏（手机号留前2后2、Token 留 SHA256 指纹） |

### 绝对禁止

- DoS / 并发轰炸 / 无限循环
- 修改/删除/覆盖别人的数据
- 扫描内网端口/服务
- 上传 webshell 到生产环境
- 绕过验证码（CAPTCHA）
- 绕过 MFA/两步验证
- 暴力破解真实用户账号
- 用公共 DNSLog 平台
- 对没授权的网站发起任何请求
- API Key 硬编码在代码里

### 合规

- 所有测试必须在授权范围内
- **"AI 做的"不构成法律辩护理由**
- 部分 SRC 平台明文规定：纯 AI 报告直接驳回，≥5 条拉黑
- 遵守目标所在地法律（CFAA / 网络安全法）

---

## 常见问题与排错

### 安装阶段

| 问题 | 解决方法 |
|------|---------|
| `go install` 报错 "command not found" | Go 没装或者没加到 PATH。重装 Go 并确保 `~/go/bin` 在 PATH 里 |
| `pip install` 报权限错误 | 加 `--user`：`pip install --user -r aimy/requirements.txt` |
| `bash` 命令找不到 | Windows 用 Git Bash 或 WSL。PowerShell 里 `bash` 不可用 |
| enscan 找不到 config.yaml | 确保 `config.yaml` 和 `enscan.exe` 在同一个目录 |

### 运行阶段

| 问题 | 解决方法 |
|------|---------|
| `httpx` 报 "dependencies not installed" | Python 的 httpx 和 Go 的 httpx 冲突了。把 `~/go/bin` 放到 PATH 最前面 |
| subfinder 限流不返回结果 | 正常现象，等等再跑。或者用 crt.sh 兜底 |
| nuclei 全部超时 | 目标可能下线了，或者防火墙把你的 IP 封了。先用 curl 手动测一个域名 |
| 被 WAF（Web 防火墙）拦截 | 读 `skills/waf-bypass-techniques/SKILL.md`，有编码升级策略 |
| 429 Too Many Requests | 正常，断路器会自动停 5 分钟。不要手动重试 |
| 503 Service Unavailable | 对方服务挂了或者把你封了。等 10 分钟，下次降低并发 |
| OneForAll 报 import 错误 | 重新跑 `pip install -r ~/tools/OneForAll/requirements.txt` |
| LLM 返回乱码或空 | 检查 `.env` 里的 API Key 是否正确，检查网络能不能连到 API 服务器 |

### 挖洞阶段

| 问题 | 解决方法 |
|------|---------|
| 侦察跑完了但什么也没发现 | 正常，不是所有目标都有漏洞。换一个资产多的目标试试 |
| AI 说发现了漏洞但无法复现 | 用 `/validate` 过验证门。很多是 AI 的幻觉 |
| 反射 XSS 被自动过滤了 | 老鸟模式默认跳过反射 XSS。切到菜鸟模式可以看到 |
| 不确定该不该提交 | 跑 `/validate`，8 问门会自动判断。Q7 不过就不要提交 |

---

## 工具清单

### Go 工具（21 个，自动安装）

| 工具 | 用途 | 一句话 |
|------|------|--------|
| subfinder | 子域名被动收集 | 从 50+ 个数据源找子域名 |
| amass | 子域名枚举 | OWASP 旗舰侦察工具 |
| assetfinder | 子域名收集 | 轻量快速 |
| httpx | HTTP 存活检测 | 探活 + 技术栈指纹 |
| dnsx | DNS 解析 | 批量 DNS 查询 |
| naabu | 端口扫描 | 快速端口探测 |
| nuclei | 漏洞模板扫描 | 上千个 CVE 一键扫 |
| katana | JS 爬虫 | 深度爬取单页应用 |
| gau | 历史 URL | 从 AlienVault/CommonCrawl/Wayback 收集 |
| waybackurls | Wayback Machine | 从互联网档案馆拉 URL |
| hakrawler | Web 爬虫 | 快速爬取 |
| ffuf | 模糊测试 | 目录/参数暴力破解 |
| interactsh-client | OOB 回调 | 盲漏洞的外带检测 |
| dalfox | XSS 扫描 | 专业参数分析和 XSS 检测 |
| alterx | 排列变异 | NLP 分词生成子域名变体 |
| anew | 去重追加 | 给文件追加新行并去重 |
| asnmap | ASN 映射 | IP→ASN→组织 |
| gf | URL 分类 | 把 URL 按漏洞类型分桶 |
| getJS | JS 提取 | 从页面提取 JS 文件 |
| trufflehog | 密钥扫描 | 检测泄露的 API Key/密码 |
| uncover | 测绘查询 | Shodan/Censys 统一查询 |

### 企业工具（2 个）

| 工具 | 用途 |
|------|------|
| enscan | 企业工商信息：ICP 备案、分支机构、股权穿透、供应商 |
| OneForAll | 全量子域名收集，20+ 被动源 |

### Shell 管线（10 个脚本）

| 脚本 | 做什么 |
|------|--------|
| `recon_engine.sh` | 标准子域名侦察 |
| `full_recon.sh` | 七维全量侦察（含企业扩展） |
| `enscan_recon.sh` | 仅企业扩展 |
| `favicon_hunt.sh` | 图标哈希反查 |
| `asn_discovery.sh` | ASN/IP 反查 |
| `csp_intel.sh` | CSP 策略解析 |
| `js_sourcemap.sh` | JS Source Map 还原 |
| `cdn_origin.sh` | CDN 真实 IP 溯源 |
| `safety_precheck.sh` | 发包前安全门禁 |
| `setup-tools.sh` | 一键安装全部工具链 |

---

## 架构

```
AIMY/
├── aimy/                      Python 框架 (261 .py)
│   ├── core/                  调度器 · ReAct 循环 · 状态机 · 阶段管理
│   ├── tools/                 120+ 漏洞检测器 · HTTP 客户端 · 安全门禁
│   │   ├── ssrf_detector.py    SSRF 检测 + OOB/interactsh
│   │   ├── sqli_blind.py       布尔/时间盲注 SQLi
│   │   ├── xss_detector.py     反射/存储/DOM XSS
│   │   ├── ssti_detector.py    20+ 模板引擎 SSTI
│   │   ├── jwt_detector.py     JWT 攻击 (alg:none、弱密钥、kid 注入)
│   │   ├── race_condition.py   TOCTOU 竞态引擎
│   │   └── ...                 115+ 更多
│   ├── memory/                 飞轮引擎 · 战报 · H1 同步 · 技法进化
│   ├── llm/                    多模型客户端 (GPT · Claude · 龙猫)
│   └── safety/                 scope 校验 · 速率控制 · 审计追踪
├── skills/                     180 攻击方法论 (每个漏洞类一个目录)
├── anthropic-skills/           8,946 防御/取证/合规技能
├── references/                 5,891 参考 (3,029 H1报告 + 52 Payload集 + 68 剧本)
├── tools/                      10 Shell 管线脚本
├── wooyun_public/              51,964 乌云历史漏洞案例
└── 彦的h1飞轮/                 116 类技法排行 + 32 顶级资源库
```

---

## 文档索引

| 文件 | 适合谁 | 内容 |
|------|--------|------|
| **README.md** | 所有人 | 本文件 — 从零到挖洞全流程 |
| **QUICKSTART.md** | 想快速上手 | 精简版安装 + 命令速查 + 排错 |
| **DISCLAIMER.md** | 所有人必读 | 授权范围 · 操作红线 · 责任限制 |
| **CLAUDE.md** | AI 用户 | Agent 身份 · 完整触发词表 (35类) · 技术栈 |
| **SKILL.md** | 高级用户 | Fusion-router 四源调度中枢 |
| **INDEX.md** | 查资料 | 全部 180 技能的索引和交叉引用 |

---

## 免责声明

> **本工具仅限已获得明确授权的环境中进行安全测试、CTF 竞赛或漏洞研究使用。未经授权使用可能违反法律法规。使用者自行承担所有责任。**
>
> 完整条款见 [DISCLAIMER.md](./DISCLAIMER.md)。
>
> 本工具**仅用于授权安全测试**。使用本工具即表示你确认：
> - 你对你使用本工具的所有行为负全部责任
> - "AI 做的"不构成法律辩护理由
> - 你有责任确保对目标拥有授权
> - 你不会提交纯 AI 生成的报告（SRC 平台会拉黑）
> - 你不会绕过内置的安全门禁
>
> 本工具按"现状"提供，作者不承担任何因使用或误用导致的损失。

MIT License — 各 Skill 文件见各自许可证。
