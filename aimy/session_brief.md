## 📊 EVX 挖洞战报 (更新于 2026-07-01 19:15)

| 指标 | 值 |
|------|----|
| 累计报告 | 10676 |
| 接受数 | 10393 |
| 接受率 | 97% |
| 累计赏金 | ¥6,412,384 |

### 🅧 XBOW高频技法 (104靶机命中分布)

| # | 类型 | XBOW靶机数 | 占比 | 速度分 | 推荐加载技能 |
|---|------|:---------:|:----:|:------:|----------|
| 1 | `xss`  | 23 | 14.6% | 1.6 | `skills/xss-cross-site-scripting/SKILL.md` |
| 2 | `default_credentials` 🆕 | 18 | 11.5% | 1.7 | `skills/ssrf-server-side-request-forgery/SKILL.md` |
| 3 | `idor`  | 15 | 9.6% | 1.3 | `skills/idor-broken-object-authorization/SKILL.md` |
| 4 | `privilege_escalation`  | 14 | 8.9% | 0.5 | `skills/ssrf-server-side-request-forgery/SKILL.md` |
| 5 | `ssti`  | 13 | 8.3% | 1.0 | `skills/ssti-server-side-template-injection/SKILL.md` |
| 6 | `command_injection`  | 11 | 7.0% | 0.8 | `skills/ssrf-server-side-request-forgery/SKILL.md` |
| 7 | `business_logic`  | 7 | 4.5% | 0.8 | `skills/ssrf-server-side-request-forgery/SKILL.md` |
| 8 | `sqli`  | 6 | 3.8% | 0.9 | `skills/sqli-sql-injection/SKILL.md` |
| 9 | `insecure_deserialization`  | 6 | 3.8% | 0.8 | `skills/deserialization-insecure/SKILL.md` |
| 10 | `lfi`  | 6 | 3.8% | 0.9 | `skills/ssrf-server-side-request-forgery/SKILL.md` |

### ⚡ 最快出结果 (优先测这些)

| # | 技法 | 类型 | 接受率 | 均赏金 | 速度分 | 加载技能 |
|---|------|------|--------|--------|--------|---------|
| 1 | open redirect in rfc6749 | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 2 | XSS and Open Redirect on MoPub Login | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 3 | Open URL Redirection | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 4 | Open Redirect (6.0.0 < rails < 6.0.3.2) | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 5 | Open Redirect in Logout & Login | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 6 | Another window.opener issue | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 7 | Host Header Injection | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 8 | Tab nabbing via window.opener | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 9 | Open Redirect in secure.showmax.com | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |
| 10 | Link filter protection bypass | `open redirect` | **100%** | ¥2 | 2.3 | `skills/open-redirect/SKILL.md` |

### ✅ 误报率最低 (确定性最高)

| # | 技法 | 类型 | 接受率 | 样本量 | 可靠性 | 加载技能 |
|---|------|------|--------|--------|--------|---------|
| 1 | memory corruption - generic | `memory corruption - generic` | **96%** | 26次 | 12.6 | `skills/deserialization-insecure/SKILL.md` |
| 2 | privilege escalation | `privilege escalation` | **96%** | 129次 | 12.6 | `skills/linux-privilege-escalation/SKILL.md` |
| 3 | insecure storage of sensitive informatio | `insecure storage of sensitive informatio` | **95%** | 19次 | 12.5 | `skills/deserialization-insecure/SKILL.md` |
| 4 | improper access control - generic | `improper access control - generic` | **94%** | 162次 | 12.4 | `skills/idor-broken-object-authorization/SKILL.md` |
| 5 | violation of secure design principles | `violation of secure design principles` | **93%** | 27次 | 12.3 | `skills/authbypass-authentication-flaws/SKILL.md` |
| 6 | improper authorization | `improper authorization` | **92%** | 11次 | 12.2 | `skills/api-authorization-and-bola/SKILL.md` |
| 7 | insufficiently protected credentials | `insufficiently protected credentials` | **100%** | 9次 | 12.0 | `skills/authbypass-authentication-flaws/SKILL.md` |
| 8 | deserialization of untrusted data | `deserialization of untrusted data` | **90%** | 18次 | 12.0 | `skills/deserialization-insecure/SKILL.md` |
| 9 | use of hard-coded credentials | `use of hard-coded credentials` | **100%** | 6次 | 12.0 | `skills/credential-attack/SKILL.md` |
| 10 | modification of assumed-immutable data ( | `modification of assumed-immutable data (` | **100%** | 9次 | 12.0 | `skills/business-logic-vulnerabilities/SKILL.md` |

### 🔒 幻觉最少 (Validato+Canary双确认)

| # | 技法 | 类型 | 接受率 | 验证方式 | 加载技能 |
|---|------|------|--------|---------|---------|
| 1 | SQLi: PostgreSQL error-based: CAST((SELE | `sqli` | **100%** | Validator确认 ✅ | `skills/sqli-sql-injection/SKILL.md` |
| 2 | Missing length validation of user displa | `rce` | **100%** | Validator确认 ✅ | `skills/cmdi-command-injection/SKILL.md` |
| 3 | Verbose SQL error messages | `information disclosure` | **100%** | Validator确认 ✅ | `skills/insecure-source-code-management/SKILL.md` |

### <M4>最顶尖的测试思路 (创造力分最高)

| # | 技法 | 类型 | 创造力 | 特色 | 加载技能 |
|---|------|------|--------|------|---------|
| 1 | Range constructor type confusion DoS | `rce` | 2.0 | <M3>非常见 | `skills/cmdi-command-injection/SKILL.md` |
| 2 | Privilege escalation in workers container | `privilege escalation` | 2.0 | <M3>非常见 | `skills/linux-privilege-escalation/SKILL.md` |
| 3 | Cloud Computer Hackerone Triager can be Acces | `business logic` | 2.0 | <M3>非常见 | `skills/business-logic-vulnerabilities/SKILL.md` |
| 4 | [Spot Check] - Ability to disclose metadata a | `information disclosure` | 2.0 | <M3>非常见 | `skills/insecure-source-code-management/SKILL.md` |
| 5 | A potential risk in the aws-lambda-ecs-run-ta | `privilege escalation` | 2.0 | <M3>非常见 | `skills/linux-privilege-escalation/SKILL.md` |
| 6 | CSS Injection via Client Side Path Traversal  | `xss` | 2.0 | <M3>非常见 | `skills/xss-cross-site-scripting/SKILL.md` |
| 7 | Nextcloud 10.0 privilege escalation issue - N | `privilege escalation` | 2.0 | <M3>非常见 | `skills/linux-privilege-escalation/SKILL.md` |
| 8 | Unauthorized Kubernetes to RCE (root) and fou | `rce` | 2.0 | <M3>非常见 | `skills/cmdi-command-injection/SKILL.md` |
| 9 | ci.nextcloud.com: CVE-2015-5477 BIND9 TKEY Vu | `rce` | 2.0 | <M3>非常见 | `skills/cmdi-command-injection/SKILL.md` |
| 10 | doc.owncloud.com: CVE-2015-5477 BIND9 TKEY Vu | `denial of service` | 2.0 | <M3>非常见 | `skills/active-directory-certificate-services/SKILL.md` |

### <M1>别人想不到的挖洞思路 (冷门技巧)

- 第三方回调:webhook/callback/SSO回调地址常被信任.
- API响应多出字段不忽略,下个接口可能用它做权限判断.
- 错误信息差异:用户名不存在vs密码错误,可枚举用户名.
--- 业务逻辑骚思路 ---
- 跨天限额重置:23:59发两笔,Cron重置限额后第二笔绕过限制
- 或权限缝隙:role=admin或部门负责人,没限定当前部门->跨部门拿数据
--- 迂回攻击链:子公司->收购品牌->海外站->主站 ---
- CSP/跨域信任链:子公司域名在主站CSP白名单中->子公司XSS即可绕过主站CSP
- 子域名接管链:找子公司的CNAME指向已删除的云服务->接管子域名->利用通配符cookie打主站
--- SRC终极脑洞(99%人想不到) ---
- AI密钥泄露:搜OPENAI_API_KEY/ANTHROPIC_API_KEY/sk-proj-xxx/sk-ant-xxx
- 异步SSRF蓝海:SVG/PDF上传->URL导入->webhook->OOB payload->几小时后回调到
--- 核心心法 ---
- 盲漏洞需要OOB信道 -- 没有Interactsh等于没测

### <M6>危害提升链 (发现漏洞后可升级方向)

| # | 发现 | 升级方向 | 危害提升 | 路径 |
|---|------|---------|---------|------|
| 1 | `xss` | XSS->CSRF->ATO | medium->critical | XSS+CSRF->ATO |
| 2 | `ssrf` | SSRF->cloud metadata->IAM | high->critical | SSRF访问cloud metadata->IAM凭证 |
| 3 | `sqli` | SQLi->OUTFILE->RCE | high->critical | MySQL INTO OUTFILE写webshell->RCE |
| 4 | `idor` | IDOR->批量泄露 | high->critical | 遍历ID参数->大量用户数据泄露 |
| 5 | `lfi` | LFI->log poison->RCE | high->critical | LFI读access.log->User-Agent注PHP->RCE |
| 6 | `xxe` | XXE->SSRF | high->critical | XXE通过SYSTEM entity发内网请求 |
| 7 | `cmdi` | CMDi->reverse shell | critical->critical | bash reverse shell->完全控制服务器 |
| 8 | `csrf` | CSRF->ATO | medium->critical | CSRF修改邮箱/密码->账号接管 |
| 9 | `ssti` | SSTI->RCE | high->critical | 模板引擎执行系统命令->RCE |
| 10 | `jwt` | JWT alg=none | high->critical | JWT修改alg为none->伪造任意用户 |

### <M9>如何利用此战报

1. **🅧 XBOW高频技法** -> 基于104靶机真实分布，优先测命中率高的类型
2. **⚡ 最快出结果** -> 先试这些,10分钟就能验证有无漏洞
3. **✅ 误报率最低** -> 这些值得写报告,不会被拒
4. **🔒 幻觉最少** -> Validator+Canary代码级验证过的,100%可信
5. **最顶尖思路** -> 链式攻击/非常见协议/高创造力技法
6. **别人想不到** -> 冷门技巧,每天轮换,开阔思路
7. **危害提升链** -> 发现漏洞后查这个表,看能不能升级到Critical
8. **读技能文件** -> 点击加载技能列的文件,看完整方法论
9. **举一反三** -> 成功技法拆解->变体->同类端点全覆盖