# ⚔️ 彦 — 实战挖洞手册

> 位置: `C:\Users\PC\Desktop\彦`
> 用法: 每次挖洞前通读一遍，按清单打勾

---

## 📋 目录

```
挖洞前准备     → 账号 / Scope / 工具 / 战报
Phase 0        → 红线确认（3 秒）
Phase 1        → 接单（5 分钟）
Phase 2        → 六维被动侦察（零发包）
Phase 3        → 主动枚举（限速）
Phase 4        → 信号驱动狩猎
Phase 5        → 验证门（8 问 + 4 关）
Phase 6        → 报告提交
Phase 7        → 飞轮复盘
挖完收工       → 退出条件 / 善后
故障兜底       → 工具崩了 / 被 WAF / 没思路
```

---

## 🟢 挖洞前准备（每次必做）

### □ 1.1 测试账号

```
IDOR/越权测试 → 至少需要 2 个不同权限账号
  Account A: 普通用户
  Account B: 另一个普通用户（不同租户）
  Admin:     管理员（如果有）

在哪里注册？
  □ 有公开注册 → 注册 A/B 两个号
  □ 没有注册 → 找测试账号/申请试用/检查 HTML 注释里的 test:test
  □ 都不行 → SSO/OAuth 测试账号，或降低预期（只测无需认证的）
```

### □ 1.2 读战报

```bash
# 本周高命中技法排行 → 先攻哪些漏洞类
python -m aimy.memory.session_brief
```

### □ 1.3 读排除记录

```
# 之前已经试过什么，省得重复尝试
read 彦的h1飞轮/06_排除记录.md
```

### □ 1.4 准备 OOB 监听

```
Blind 漏洞验证需要（SSRF / XXE / Blind SQLi / RCE OOB）:

方案 A（推荐）: Burp Collaborator
  已连 Burp MCP，可直接用：
  collaborator_create_client → 拿域名
  collaborator_generate_payload → 注入
  collaborator_poll → 查回连

方案 B: 自建 interactsh
  # 启动
  docker run -d -p 80:80 -p 443:443 projectdiscovery/interactsh-server

方案 C（不用）: 公共 DNSLog — 禁止使用（其他挖洞者能看到你的数据）
```

### □ 1.5 Scope 再确认

```
Phase 2 会发现子域 → 必须核对是否在授权范围内

规则：
  ☐ *.target.com → 所有子域都算在 scope 内
  ☐ target.com 但排除 *.dev.target.com → dev 子域不能碰
  ☐ 只列举了几个域 → 只测列出的，新发现的不能碰
```

### □ 1.6 时间盒

```
写入 wall clock:

  开始: _______________
  结束: _______________
  弹性: +1h / 不加 / 到点停
```

### □ 1.7 安全模式确认

```bash
# 默认 bounty 模式 + Safety Gate 开启
AIMY_SCENE=bounty    # 只读，不写数据
python aimy.py --list-providers   # 确认模型可用
```

---

## 📌 Phase 0: 红线（全程适用，违反即停）

```
☐ ≤1 req/s · 并发 ≤3 · 日配额 ≤500
☐ curl --max-time 10 --limit-rate 100K （已内置）
☐ 不碰 out-of-scope
☐ 不扫内网（除授权）
☐ 不绕过验证码
☐ 不绕过 MFA
☐ 不暴力破解真实用户账号
☐ 最多取 3 条用户数据，验证即停
☐ 发现数据泄露立即停止
☐ 不用公共 DNSLog
☐ 所有 payload 先过 Safety Gate（DROPs 自动净化）
```

---

## 📌 Phase 1: 接单（5 分钟）

```
目标公告 URL: _______________________
程序名称: ___________________________

In-scope:
  □ _______________________________
  □ _______________________________
  □ _______________________________

Out-of-scope:
  □ _______________________________
  □ _______________________________

赏金:
  □ 高危范围: _____ ~ ______
  □ 严重范围: _____ ~ ______
  □ 低危是否收: 是 / 否

SLA: _______________________________
```

---

## 📌 Phase 2: 六维被动侦察（零发包）

> **不发包**，只查第三方数据源。
> 6 维中覆盖 ≥3 维才算通过。

### □ 维度 1: 子域名被动

```bash
# 从 4 个源收集
crt.sh:     curl -s "https://crt.sh/?q=%25.target.com&output=json"
Chaos:      curl -s "https://chaos.projectdiscovery.io/api/v1/programs"  # 需 key
subfinder:  subfinder -d target.com -all -silent
amass:      amass enum -passive -d target.com -o /dev/null

# 合并去重
cat sources/*.txt | sort -u > recon/subs_passive.txt
wc -l recon/subs_passive.txt
```

### □ 维度 2: 排列变异

```bash
# 用已有子域做排列
dnsgen recon/subs_passive.txt | dnsx -silent > recon/subs_perm.txt
alterx -l recon/subs_passive.txt | dnsx -silent >> recon/subs_all.txt
```

### □ 维度 3: 图标关联

```bash
# 算 mmh3 hash → 查 FOFA/Shodan
python -c "
import mmh3, requests, base64, codecs
r = requests.get('https://target.com/favicon.ico')
icon = base64.encodebytes(r.content)
hash = mmh3.hash(codecs.decode(icon, 'base64'))
print(f'icon_hash={hash}')
# → 去 fofa.info 搜 icon_hash={hash}
# → 去 shodan.io 搜 http.favicon.hash:{hash}
"
```

### □ 维度 4: ASN / IP 反查

```bash
# 找 ASN
asnmap -d target.com

# IP 范围 → 反向查域名
amass intel -addr <IP_RANGE> -whois
```

### □ 维度 5: CSP 反查

```bash
# 从主站响应头提取可信域名
curl -sI https://target.com | grep -i content-security-policy

# 提取域名（trusted-sources）→ httpx 验证存活
```

### □ 维度 6: JS 源码还原

```bash
# 收集 JS
katana -u https://target.com -jc | grep '\.js' > js_urls.txt
gau --js target.com >> js_urls.txt

# 还原 source map
python -c "
import requests, json
for js in js_urls:
    map_url = js + '.map'
    r = requests.get(map_url)
    if r.status_code == 200:
        # source-map-unpack 或反序列化 map 文件
        print(f'Source map found: {map_url}')
"
```

### □ 输出: 活资产清单

```
asset清单.txt 包含:
  域名 | IP | 技术栈 | 状态码 | 标题 | JS端点

来源 ≥3 维才算合格:
  ☐ 子域名被动
  ☐ 排列变异
  ☐ 图标关联 / ASN / CSP / JS（至少 1 个补充）
```

### Burp MCP 补充（只读）

```
proxy_history     → 查看已有流量（如果有历史记录）
sitemap_query     → 查已发现端点
passive_intel     → 自动扫描 API Key / Token / JWT / 内网 IP
```

---

## 📌 Phase 3: 主动枚举（限速发包）

> **pre-flight 确认**：输出目标数 × 请求数 × 预期影响后，等用户回复确认

```
活资产: ______ 个
预计请求: ______ 次
预计耗时: ______ 分钟
```

### □ 端口扫描

```bash
python main.py portscan
# 或 naabu -l recon/subs_passive.txt -top-ports 1000 -rate 1
```

### □ 目录枚举

```bash
python main.py dirfuzz -l recon/subs_passive.txt
# 或 ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -rate 1
```

### □ 参数挖掘

```bash
python tools/param_miner.py -l recon/host_tech.txt
# 或 arjun -u https://target.com/api/endpoint --rate-limit 1
```

### □ WAF 识别

```bash
python main.py waf
# 或 wafw00f https://target.com
```

### □ 指纹匹配（条件触发）

```
如果指纹含以下关键字，必须读配套默认口令表：

  国产 OA:       → references/dictionaries/default-credentials-cn.md
  中间件:        → references/dictionaries/chinese-srcfingerprints.md
  WordPress:    → wpscan
  Joomla:       → joomscan
  Tomcat:       → /manager/html 默认密码
  Jenkins:      → /script 未授权
  Kubernetes:   → /api/v1/namespaces
  MinIO:        → 默认 minioadmin:minioadmin
```

### □ 输出: 资产矩阵

```
host_tech.txt:
  域 | 端口 | 服务 | 指纹 | 状态码 | JS 端点 | WAF

重点标记:
  □ 管理后台 (/admin, /manager)
  □ API 端点 (/api, /graphql, /swagger)
  □ 登录/注册 (/login, /signup)
  □ 文件上传 (/upload, /import)
  □ .git/.env/备份 (/backup, /.git/config)
```

---

## 📌 Phase 4: 信号驱动狩猎

> **核心规则**: 看信号 → Read 对应 Skill → 用 Skill 里的 payload → 不准凭记忆

### □ 信号 → Playbook 映射表

扫描资产矩阵，找到以下入口信号：

```
┌──────────────────────────────────────────────────────────────────┐
│ 信号                     │ 打什么            │ Read 哪个 Skill    │
├──────────────────────────────────────────────────────────────────┤
│ URL 有 ?url=/path        │ SSRF / LFI        │ ssrf / file-access  │
│ URL 有 ?file=, ?page=    │ LFI / 路径遍历    │ file-access-vuln    │
│ URL 有 ?redirect=, ?next=│ 开放重定向        │ open-redirect       │
│ Cookie 有 JWT (eyJ...)   │ JWT 攻击          │ jwt-oauth-token     │
│ 用户 ID 可遍历 (/user/1) │ IDOR              │ idor-broken-author  │
│ REST API (/api/...)      │ BOLA / MassAssign │ api-authorization   │
│ 搜索框 / 输入回显        │ XSS               │ xss-cross-site      │
│ 登录 / 注册 / 密码重置   │ 认证绕过          │ authbypass-authent  │
│ SQL 报错 / 参数见 DB     │ SQL 注入          │ sqli-sql-injection  │
│ 支付 / 订单 / 优惠券     │ 业务逻辑          │ business-logic      │
│ GraphQL 端点             │ GraphQL 注入      │ graphql-audit       │
│ 并发操作 (抢购/抽奖)     │ 条件竞争          │ race-condition      │
│ 文件上传                 │ 文件上传 + 解析   │ file-access-vuln    │
│ XML / SVG 上传           │ XXE               │ xxe-xml-external    │
│ 模板渲染 ({{ )           │ SSTI              │ ssti-template-inj   │
│ 序列化 (二进制/JSON)     │ 反序列化          │ deserialization     │
│ OAuth / SSO / SAML       │ OAuth 滥用        │ oauth-oidc-misconf  │
│ CORS 头 (Access-Control-)│ CORS 配置         │ cors-cross-origin   │
│ Host 头可改              │ Host 注入         │ http-host-header    │
│ 403 / 401                │ 权限绕过          │ 401-403-bypass      │
│ .git/.env/备份文件       │ 源码泄露          │ insecure-source-cm  │
│ WebSocket 连接           │ WS 安全           │ websocket-security  │
│ /actuator / /swagger     │ 信息泄露          │ recon-for-sec       │
│ 反代 + CL.TE             │ HTTP Smuggling    │ request-smuggling   │
│ CDN/缓存                 │ 缓存投毒/欺骗     │ web-cache-deception │
│ __proto__ / constructor  │ 原型链污染        │ prototype-pollution │
│ 验证码 / 人机验证        │ WAF 绕过          │ waf-bypass-techniq  │
│ LLM / 聊天机器人         │ Prompt 注入       │ llm-prompt-inject   │
│ 慢响应 / 大数据量        │ ReDoS / 算法攻击  │ dos via 扩展        │
└──────────────────────────────────────────────────────────────────┘
```

### □ 抓取流程

```
发现信号
   │
   ▼
Read 对应 Skill（不准凭记忆）
   │
   ▼
按 Skill 的五段式执行:
  Persona → Context → Examples → Instructions → Output
   │
   ▼
发包验证（过 Safety Gate）
   │
   ├─ 命中 → 立即存证据 → 入 Phase 5 候选
   ├─ WAF 拦截 → 读 02-bypass-toolkit.md 决策树
   └─ 无信号 → 04-control-gap-hunting.md
```

### □ 证据纪律（命中后立即做）

```
☐ 保存完整 HTTP 请求（curl -v 格式）
  文件位置: evidence/{vuln_type}/{timestamp}_request.txt

☐ 保存完整 HTTP 响应
  文件位置: evidence/{vuln_type}/{timestamp}_response.txt

☐ 截图（命令行输出 / Burp 界面）
  文件位置: evidence/{vuln_type}/{timestamp}.png

☐ 记录复现步骤（精确到可执行）
  文件位置: evidence/{vuln_type}/{timestamp}_steps.md
```

### □ 发现优先级排序

```
同时命中多个可疑点时，按这个顺序验证:

  1. SSRF / RCE → 最高赏金
  2. 认证绕过 → 解锁更多功能
  3. IDOR → 数据越权
  4. SQLi → 数据库访问
  5. 业务逻辑 → 常见高赏金
  6. XSS → 中低赏金
  7. 其他
```

### □ Burp MCP 辅助通道

```
按场景选工具:

  手动发包调试:    repeater_send
  SSRF OOB 验证:  collaborator_*
  IDOR 越权:      auth_diff（三角色对比）
  竞态测试:       http_race
  参数枚举:       intruder_send / http_fuzz
  WAF 绕过:       intruder_* + http_fuzz
  SQLi:           http_send_request + analyze_response
  XSS:            repeater_send + analyze_find_reflected
  反射点定位:     analyze_find_reflected
  对比分析:       analyze_diff（请求/响应对比）
```

### □ 卡壳兜底

```
所有信号走完一遍还是没找到:

  Step 1 → references/SRC_终极脑洞.md
           时光机考古、WayBack 翻旧版、对比历史版本差异

  Step 2 → references/业务逻辑拓展骚思路.md
           对称→非对称思维、边界条件、幂等性、状态机

  Step 3 → 彦的h1飞轮/05_举一反三机制.md
           成功技法变体 → 同类端点多场景测试

  Step 4 → 彦的h1飞轮/06_排除记录.md
           已经试过什么，省得重复

  Step 5 → 换个模型再试
           python aimy.py -p claude -t target.com  # 龙猫→Claude 换视角
```

---

## 📌 Phase 5: 验证门（8 问 + 4 关）

### □ Q1-Q8 顺序执行（一票否决）

```
Q1: 攻击者能 step by step 复现吗？
    写不出 HTTP 请求/curl 命令 → 停
    ☐ 通过  ☐ 否决

Q2: 影响在程序的接受列表里吗？
    SQLi / RCE / SSRF → 通常接受
    自 XSS / 信息泄露 / 配置问题 → 可能不接受
    ☐ 通过  ☐ 否决

Q3: 根因在 scope 资产上吗？
    用了第三方服务、CDN、SaaS → 不在 scope 就停
    ☐ 通过  ☐ 否决

Q4: 需要攻击者不可能拿到的权限吗？
    管理员才能触发 → 通常不算安全漏洞
    但：管理员功能 + IDOR → 可能算
    ☐ 通过  ☐ 否决

Q5: 这是已知/已接受行为吗？
    文档写了的功能 → 停
    其他研究员已经报过 → 停
    ☐ 通过  ☐ 否决

Q6: 能证明实际业务影响吗？
    拿到数据？执行命令？越权操作？
    不能证明对真实用户有影响 → 降级
    ☐ 通过  ☐ 降级

Q7: 在禁止提交清单里吗？
    常见: 自 XSS、反射 XSS（无 impact）、open redirect、
          缺少安全头、版本信息泄露、SPF/DMARC、CORS（无凭证）
    在 → 停
    ☐ 通过  ☐ 否决

Q8: 换个 session/cookie 还能复现吗？
    不能 → 可能是你账号特有的配置问题
    但：如果是逻辑漏洞（只有你的账号有这个功能）→ 不算一票否决
    ☐ 通过  ☐ 否决
```

### □ 4 验收门（全过才写报告）

```
Gate 0: Reality Check（30 秒）
  确认真实复现 — 重新跑一遍 curl 命令
  ☐ 再次复现成功

Gate 1: Impact（2 分钟）
  攻击者能拿到什么？
  ☐ 数据 / ☐ 代码执行 / ☐ 权限提升 / ☐ 其他
  如果 Impact = "无"，停

Gate 2: Dedup（5 分钟）
  ☐ 搜 Hacktivity:   "target.com <关键词>"
  ☐ 搜 GitHub:       "target.com <漏洞特征>" 
  ☐ 搜 Google:       "site:hackerone.com target.com <关键词>"
  ☐ 搜 SRC 平台:     看历史已提交报告

Gate 3: Report Quality（10 分钟）
  ☐ 标题公式: [漏洞类型] in [端点] allows [攻击者] to [影响]
  ☐ 复现步骤: 精确到复制粘贴能跑
  ☐ 证据: HTTP 包 / 截图 / curl 命令
  ☐ CVSS 4.0 向量
  ☐ 影响: 结合业务讲清楚
  ☐ PII 脱敏: 手机/邮箱留前2后2，Token 留前2后2
```

### □ Validator 自动验证

```
# 已有 XBOW 风格的确定性验证器
# 命中后自动调用，不用手动跑

自动完成:
  ✓ SimHash 去重
  ✓ curl 复现 → True/False
  ✓ Canary OOB 二次确认
  ✓ 结果写入 FeedbackDB
```

---

## 📌 Phase 6: 报告提交

### □ 前置阅读（不准跳）

```bash
# 合规红线
Read references/compliance.md

# H1 模板
Read references/templates/report-submission.md

# SRC AI 报告红线（360SRC 明文禁止纯 AI 报告）
Read 彦的h1飞轮/07_SRC_AI报告红线.md  # 如果存在
```

### □ 报告三段式

```
标题: [漏洞类型] in [端点] allows [攻击者] to [影响]
  例: "SQL Injection in /api/users/search allows attacker to extract database contents"

步骤:
  1. 确保有测试账号 / 环境
  2. 发送以下请求:
     ```
     curl -v 'https://target.com/api/users/search?q=test' \
       -H "Authorization: Bearer <token>"
     ```
  3. 观察响应: __________________
  4. 修改 payload 为: __________________
  5. 响应变为: __________________
  6. 结论: __________________

影响:
  CVSS 4.0 向量: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/...
  业务影响: __________________________________

证据:
  □ HTTP 请求/响应包
  □ 截图 / 终端输出
  □ curl 命令（可复现）
```

### □ PII 脱敏强制

```
☐ 手机号 → 留前2后2: "138******12"
☐ 邮箱 → 留前2后2: "te***@example.com"
☐ Token / Cookie → 留前2后2
☐ IP → 打码末段: "192.168.xxx.xxx"
☐ 真实姓名 → 打码
☐ 报告中所有敏感信息遵循最小暴露原则
```

---

## 📌 Phase 7: 飞轮复盘

### □ 自动（每次命中后自动触发）

```
✓ record_finding() → 三层存储
  PatternDB（跨目标模式学习）
  FeedbackDB（反馈数据库）
  HuntJournal（事件日志）

✓ 成功技法 → techniques.jsonl 记录
✓ 高评分(exceptional) → skill_candidates.json 写入
```

### □ 手动跑飞轮

```bash
# 完整飞轮（需要 H1 token）
python aimy.py --flywheel

# 跳过 H1 同步
python aimy.py --flywheel --skip-h1
```

### □ 查看飞轮结果

```bash
# 本周推荐
cat ~/.aimy/session_brief.md

# 历史命中技法
cat ~/.aimy/patterns.jsonl | tail -20

# 值得写 Skill 的候选
cat ~/.aimy/skill_candidates.json

# H1 报告评分排名
cat ~/.aimy/h1_rankings.jsonl | head -5
```

---

## 🟢 挖完收工

### □ 退出条件

```
全部满足时才退出:

  ☐ 所有入口信号走完一遍
  ☐ 所有 Phase 3 资产至少过了一个对应的 playbook
  ☐ 卡壳兜底翻过（至少 Step 1-3）
  ☐ 时间盒没超: ______ (当初设的)
```

### □ 善后

```
☐ 没有遗留的 Burp Collaborator 会话
☐ evidence/ 目录整理好了
☐ 如果有发现没来得及出报告 → 记录到 06_排除记录.md 或待办
```

---

## 🔧 故障兜底

### 工具崩了怎么办

```
subfinder 限流:
  → 等 30 秒重试
  → 换 curl -s "https://crt.sh/?q=%25.target.com&output=json"

httpx 全超时:
  → 不是目标全挂了，就是被 WAF 拦了
  → 换 --timeout 5 试试
  → 用 curl 手动测一个看看

nuclei 跑不出结果:
  → 不是没漏洞，是 nuclei 只跑已知 CVE
  → 业务逻辑 / IDOR / 认证绕过 → nuclei 测不出，手动测

katana 爬不到 JS:
  → 目标可能是 SPA（Vue/React）
  → 换 playwright_auth.py 渲染
  → 或手动翻页面源码找 .js 路径
```

### 被 WAF 拦了

```
→ 读 02-bypass-toolkit.md 决策树
  优先级:
    1. URL 编码绕 (double URL, unicode)
    2. 大小写混写 (SQL 关键字)
    3. 注释插入 (/**/)
    4. 编码变体 (hex, base64)
    5. HTTP 方法切换 (GET→POST)
    6. 添加假参数
    7. 换协议 (HTTP/1.1 → HTTP/2)

→ 或换工具:
  python main.py waf  # 识别 WAF 类型
  → CloudFlare / ModSecurity / AWS WAF / Imperva → 各有不同绕过技术
```

### 完全没思路

```
→ references/SRC_终极脑洞.md
  "看不到攻击面不是因为没有漏洞，而是没用对视角。"

→ 换模型再来一轮:
  python aimy.py -p claude -t target.com
  python aimy.py -p deepseek -t target.com

→ 问自己:
  1. 这个应用最值钱的数据在哪？
  2. 用户最常操作什么功能？
  3. 哪些功能涉及多步流程？
  4. 哪些端点返回了不该返回的数据？
  5. 换一个攻击者拿到 codebase 会怎么挖？
```

---

## 📦 速查命令板

```bash
# === 启动挖洞 ===
python aimy.py -p longcat -t target.com

# === 指定模型 ===
python aimy.py -p claude -t target.com       # Claude
python aimy.py -p deepseek -t target.com      # DeepSeek
python aimy.py -p gemini -t target.com        # Gemini

# === 阶段切换 ===
AIMY_SCENE=pentest python aimy.py ...         # 渗透模式（需授权）
AIMY_READ_ONLY=0 python aimy.py ...           # 关只读（挖靶机）

# === 飞轮 ===
python aimy.py --flywheel                     # 完整飞轮
python aimy.py --flywheel --skip-h1           # 跳过 H1 同步

# === 辅助 ===
python aimy.py --list-providers               # 看哪些模型可用
python aimy.py -q "hunt target.com"           # 单次查询
```

---

> 最后更新: 2026-07-02
> 这本手册覆盖了从接单到复盘的全流程。
> **默认开只读，你只负责判断和决策，机器负责执行。**
