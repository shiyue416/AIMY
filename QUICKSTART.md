# 快速入门 — 5 分钟上手挖洞

> 前置条件：Python 3.10+、Git、一个 LLM API Key（GPT-5.5 或兼容）。
> 本指南默认 **赏金模式**（只读、证明即停）。渗透/红队模式见[模式说明](#运行模式)。

---

## 0. 安装配置

```bash
git clone https://github.com/shiyue416/AIMY.git && cd AIMY
pip install -r aimy/requirements.txt
cp .env.example .env
# 编辑 .env，至少填入 GPT5_API_KEY=sk-xxx
```

## 1. 验证环境

```bash
python aimy.py --list-providers      # 确认 LLM 连通
python -m aimy.memory.session_brief  # 查看本周高命中技法排行
```

## 2. 开始挖洞

```bash
# 完整流程（侦察 → 挖洞 → 验证 → 报告）
/recon target.com
/hunt target.com
/validate
/report
```

单命令入口：

```bash
python aimy.py --target target.com
```

---

## 命令速查 — 什么情况用什么

| 你想做什么 | 命令 |
|-----------|------|
| 发现所有子域名和资产（零发包） | `/recon target.com` |
| 针对某个漏洞类深挖 | `/hunt target.com --vuln-class ssrf` |
| 全面覆盖 26 种漏洞类（不遗漏） | `/hunt target.com --autonomous` |
| 提交前验证一个发现 | `/validate` |
| 生成可提交的报告 | `/report` |
| 按赏金平台格式出报告 | `/report bounty` |
| 继续上次中断的挖洞 | `/resume target.com` |
| 查看当前挖洞进度 | `/status` |

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
Phase 2  □ ≥3/6 侦察维度  □ 资产清单输出     □ 技术栈指纹识别
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
| subfinder 限流 | 换 crt.sh：`curl -s "https://crt.sh/?q=%25.target.com&output=json"` |
| httpx 全超时 | 加 `--timeout 5`，先用 curl 手动测一个 |
| 被 WAF 拦 | 读 `skills/waf-bypass-techniques/SKILL.md` → 编码升级阶梯 |
| SPA 抓不到 JS | 用 playwright 引擎：`python aimy/tools/playwright_engine.py` |
| 完全没思路 | 换模型再来：`python aimy.py -p claude -t target.com` |
| 被限速（429） | 等 5 分钟，断路器自动触发 |
| 被封（503） | 等 10 分钟，检查 scope，降低并发 |

---

## 参考文档

| 文档 | 内容 |
|------|------|
| [README.md](./README.md) | 完整架构、模式、技能表、安全规则 |
| [SKILL.md](./SKILL.md) | Fusion-router 四源调度中枢（1033 行） |
| [INDEX.md](./INDEX.md) | 完整技能索引 + 交叉引用 |
| [CLAUDE.md](./CLAUDE.md) | Agent 身份定义、约定、优先级 |
