# 快速入门 — 从零到挖洞

> 前置条件：Windows 10+ / Linux / macOS、Git、Go 1.21+、Python 3.10+。
> 本指南默认 **赏金模式**（只读、证明即停）。

---

## 0. 环境安装

### 0.1 基础依赖

```bash
# 克隆仓库
git clone https://github.com/shiyue416/AIMY.git && cd AIMY

# Python 依赖
pip install -r aimy/requirements.txt

# LLM 配置
cp .env.example .env
# 编辑 .env，至少填入一个 LLM API Key
```

### 0.2 Go 工具链 (21 个)

> 资产收集核心——子域名、存活验证、端口扫描、URL 爬取、漏洞扫描。

```bash
# 一键安装 (需 Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/003random/getJS@latest
go install -v github.com/trufflesecurity/trufflehog/v3@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest

# 验证
for t in subfinder amass assetfinder httpx dnsx naabu nuclei katana gau \
         waybackurls hakrawler ffuf interactsh-client dalfox alterx anew \
         asnmap gf getJS trufflehog uncover; do
  which "$t" && echo "  OK  $t" || echo "  MISS $t"
done
```

> **PATH 注意**: 确保 `$HOME/go/bin` 在 PATH 最前面。Python 也有一个叫 `httpx` 的包会冲突——Go 的 `httpx` 必须优先。

### 0.3 企业侦察工具

```bash
# enscan — 企业信息收集 (ICP/分支机构/股权穿透/供应商)
# 下载: https://github.com/wgpsec/ENScan_GO/releases
# Windows:
#   解压 enscan-windows-amd64.exe → 放到 $HOME/go/bin/enscan.exe
#   解压 config.yaml → 放到 $HOME/go/bin/config.yaml
# Linux/macOS:
#   解压 enscan-linux-amd64 / enscan-darwin-amd64 → 放到 $HOME/go/bin/enscan
# 验证: enscan -h

# OneForAll — 全量子域名收集 (20+ 被动源)
git clone https://github.com/shmilylty/OneForAll.git $HOME/tools/OneForAll
pip install -r $HOME/tools/OneForAll/requirements.txt
# 验证: python $HOME/tools/OneForAll/oneforall.py --help
```

### 0.4 Shell 管线部署

```bash
# 将 Shell 脚本部署到统一执行目录
mkdir -p ~/.claude/tools
cp tools/*.sh ~/.claude/tools/
chmod +x ~/.claude/tools/*.sh

# 安装 gf 模式 (URL 自动分桶)
git clone https://github.com/tomnomnom/gf ~/.gf 2>/dev/null || \
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

### 0.5 API Key 配置 (可选——按需填写)

```bash
# 测绘引擎
export FOFA_EMAIL="your@email.com"
export FOFA_KEY="your-fofa-key"
export SHODAN_API_KEY="your-shodan-key"

# ProjectDiscovery Chaos (子域名数据集)
export CHAOS_API_KEY="your-chaos-key"

# 全自动渗透 (Kali 集成)
export KALI_HOST="192.168.x.x"
export KALI_USER="root"
export KALI_KEY="$HOME/.ssh/id_rsa"
```

### 0.6 一键验证

```bash
# Python 环境
python aimy.py --list-providers

# Go 工具链 (应全部 ✅)
bash tools/setup-tools.sh

# Shell 管线
bash ~/.claude/tools/recon_engine.sh -h 2>/dev/null || echo "(usage expected)"

# 企业工具
enscan -v 2>/dev/null && echo "OK enscan" || echo "MISS enscan"
python $HOME/tools/OneForAll/oneforall.py --help 2>&1 | grep -q OneForAll && echo "OK OneForAll" || echo "MISS OneForAll"
```

---

## 1. 开始挖洞

```bash
# 标准侦察 (子域名 → 存活 → URL)
bash ~/.claude/tools/recon_engine.sh target.com

# 全量侦察 (含企业关联——需要公司名)
bash ~/.claude/tools/full_recon.sh target.com "公司名"

# 仅企业扩展
bash ~/.claude/tools/enscan_recon.sh "公司名" target.com
```

对话模式：

```bash
/recon target.com                              # Phase 2 标准侦察
/full-recon target.com "小米"                   # Phase 2 全量侦察 (含企业扩展)
/hunt target.com                               # Phase 3→4 主动探测+漏洞挖掘
/validate                                      # Phase 5 验证门
/report                                        # Phase 6 生成报告
```

单命令全自动：

```bash
python aimy.py --target target.com
```

---

## 命令速查 — 什么情况用什么

| 你想做什么 | 命令 |
|-----------|------|
| 发现所有子域名和资产（零发包） | `bash ~/.claude/tools/recon_engine.sh target.com` |
| 全量侦察（含企业关联+子公司域名） | `bash ~/.claude/tools/full_recon.sh target.com "公司名"` |
| 企业扩展（ICP+分支+股权+供应商） | `bash ~/.claude/tools/enscan_recon.sh "公司名" target.com` |
| 图标关联发现隐藏资产 | `bash ~/.claude/tools/favicon_hunt.sh --url https://target.com` |
| ASN/IP 反查 | `bash ~/.claude/tools/asn_discovery.sh --domain target.com` |
| CSP 反向情报 | `bash ~/.claude/tools/csp_intel.sh --url https://target.com --probe` |
| JS 源码还原+密钥提取 | `bash ~/.claude/tools/js_sourcemap.sh recon/target.com` |
| 针对某个漏洞类深挖 | `/hunt target.com --vuln-class ssrf` |
| 全面覆盖 26 种漏洞类 | `/hunt target.com --autonomous` |
| 提交前验证一个发现 | `/validate` |
| 生成可提交的报告 | `/report bounty` |
| 继续上次中断的挖洞 | `/resume target.com` |

---

## 信号 → Skill 自动路由表

扫描目标时看到以下信号，对应的 Skill 会自动加载。不需要手动触发。

| 信号 | 自动加载 Skill | 首发 Payload |
|------|---------------|-------------|
| `?url=` `?redirect=` `?callback=` `?webhook=` | `ssrf-server-side-request-forgery` | `http://interactsh-server/` |
| `?id=` `?user=` `/api/user/1` 数字型 ID | `idor-broken-object-authorization` | ID +1 递增 |
| `?q=` `?search=` 输入回显在 HTML 中 | `xss-cross-site-scripting` | `<img src=x onerror=alert(1)>` |
| `?file=` `?page=` `?path=` URL 含 `../` | `path-traversal-lfi` | `../../../etc/passwd` |
| SQL 报错："syntax error" "unclosed quote" | `sqli-sql-injection` | `' OR '1'='1` |
| 响应含 `{{` `{%`、报错含 "template" | `ssti-server-side-template-injection` | `{{7*7}}` |
| Cookie/Header 含 JWT (`eyJ...`) | `jwt-oauth-token-attacks` | alg:none |
| `cmd=` `exec=` `ping=` `shell=` | `cmdi-command-injection` | `; id` |
| XML 请求体、SVG 上传、`<!DOCTYPE` | `xxe-xml-external-entity` | `<!DOCTYPE x [<!ENTITY ...>` |
| 管理端点返回 403/401 | `401-403-bypass-techniques` | Header 覆盖链 |
| 支付表单、优惠码、订单流程 | `business-logic-vulnerabilities` | 负价格、并发下单 |
| JSON 含 `__proto__` `constructor` | `prototype-pollution` | `{"__proto__":{"isAdmin":true}}` |
| 响应头含 `Access-Control-Allow-Origin` | `cors-cross-origin-misconfiguration` | Origin: attacker.com |

---

## 运行模式

### 老鸟 vs 菜鸟

| 模式 | 环境变量 | 行为 |
|------|---------|------|
| 老鸟（默认） | `AIMY_MODE=veteran` | 过滤低价值漏洞，输出简洁 |
| 菜鸟 | `AIMY_MODE=rookie` | 完整说明 + 修复建议，不过滤 |

### 场景模式

| 场景 | 环境变量 | 只读 | 目标 |
|------|---------|------|------|
| 赏金（默认） | `AIMY_SCENE=bounty` | ✅ | 找到可报告的漏洞，证明即停 |
| 渗透测试 | `AIMY_SCENE=pentest` | ❌ | 完整渗透交付报告 |
| 红队 | `AIMY_SCENE=redteam` | ❌ | 杀伤链、隐蔽、持久化 |
| 全自动渗透 | `AIMY_SCENE=auto-pentest` | ❌ | 端到端自主渗透 |

---

## 安全门禁（始终开启）

每次发包前经过安全门禁：

| 门禁 | 规则 |
|------|------|
| 速率 | ≤1 req/s，≤500 次/天，并发上限 5 |
| 范围 | 只测授权域名 — 发包前必须确认 |
| 数据 | 最多取 3 条用户数据，发现泄露立刻停 |
| 不破坏 | 只读（`id`/`whoami`/`uname`），不写不删 |
| 不绕过 | 不绕过验证码、不绕过 MFA |
| 断路器 | 连续报错 >10 次 → 自动暂停 5 分钟 |

---

## 阶段关卡 — 挖洞清单

每阶段通过出口关卡才能进入下一阶段。

```
Phase 1  □ 范围确认       □ 时间盒设定       □ 规则加载完成
Phase 2  □ ≥3/7 侦察维度  □ 资产清单输出     □ 技术栈指纹识别
Phase 3  □ 端口扫描完成   □ WAF 识别完成     □ 参数映射完成
Phase 4  □ 所有信号遍历   □ 每类漏洞 ≥1 测试  □ 证据已保存
Phase 5  □ 8 问全过       □ 4 关全过          □ Validator 确认
Phase 6  □ PII 已脱敏     □ PoC 可复现        □ CVSS 已评分
Phase 7  □ 技法已记录     □ 战报已刷新
```

---

## 验证 — 8 问门

提交前每个发现必须回答：

| 问 | 问题 | 不通过 |
|----|------|--------|
| Q1 | 攻击者能一步步复现吗？ | 否决 |
| Q2 | 影响在程序的接受列表里吗？ | 否决 |
| Q3 | 根因在 scope 资产上吗？ | 否决 |
| Q4 | 是否需要攻击者不可能拿到的权限？ | 否决 |
| Q5 | 这是已知/已接受行为吗？ | 否决 |
| Q6 | 能证明实际业务影响吗？ | 降级 |
| Q7 | 在禁止提交清单里吗？ | 否决 |
| Q8 | 换个 session 还能复现吗？ | 否决 |

禁止提交清单：`自 XSS | 反射 XSS（无影响）| 开放重定向 | 缺失安全头 | 版本暴露 | SPF/DMARC | CORS（无凭证）`

---

## 报告

```bash
/report              # 所有已确认发现
/report bounty       # 赏金平台格式（H1/Bugcrowd/Intigriti）
/report pentest      # 渗透测试交付格式
```

报告模板：
```
标题:    [漏洞类型] in [端点] 允许 [攻击者] [影响]
CVSS:    CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/...
步骤:    curl -v 'https://target.com/...'
证据:    HTTP 请求/响应包 + 截图
影响:    业务层面描述
```

PII 必须脱敏：手机 `138******12`，邮箱 `te***@example.com`，Token 留前 2 + 后 2。

---

## 排错

| 症状 | 处理 |
|------|------|
| `httpx` 报 "dependencies not installed" | Python httpx 冲突——把 `$HOME/go/bin` 放到 PATH 最前面 |
| subfinder 限流 | 用 crt.sh 兜底，或等 API key 冷却期 |
| enscan 找不到 config.yaml | 确认 `config.yaml` 在 enscan.exe 同目录 |
| OneForAll 报 import error | `pip install -r $HOME/tools/OneForAll/requirements.txt` |
| nuclei 全报 timeout | 加 `-timeout 10`，检查目标是否下线 |
| 被 WAF 拦 | 读 `skills/waf-bypass-techniques/SKILL.md` → 编码升级阶梯 |
| SPA 抓不到 JS | 用 playwright 引擎：`python aimy/tools/playwright_engine.py` |
| 被限速（429） | 等 5 分钟，断路器自动触发 |
| 被封（503） | 等 10 分钟，检查 scope，降低并发 |
| Go 工具安装后找不到 | `export PATH="$HOME/go/bin:$PATH"` 加入 `~/.bashrc` |
| `gf` 报 "no such pattern" | `cp -r ~/.gf/examples/*.json ~/.gf/` |

---

## 参考文档

| 文档 | 内容 |
|------|------|
| [README.md](./README.md) | 完整架构、模式、技能表、安全规则 |
| [SKILL.md](./SKILL.md) | Fusion-router 四源调度中枢（1033 行） |
| [INDEX.md](./INDEX.md) | 完整技能索引 + 交叉引用 |
| [CLAUDE.md](./CLAUDE.md) | Agent 身份定义、约定、优先级 |
