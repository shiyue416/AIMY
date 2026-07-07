# HackSkills Index — 116 Skills Reference (融合版)

> ★ = 权威方法论 (Authoritative)　☆ = 参考/执行层 (Reference)　🆕 = CBB 新增

## 融合路由中枢
| 文件 | 说明 |
|------|------|
| `FUSION_ROUTES.md` | **融合路由中枢** — 漏洞类→权威Skill映射, 工作流阶段→Skill路由, NL→Skill路由 |

## Master Entry (start here)
| Skill | 标记 | Description |
|-------|------|-------------|
| `hack` | ★ | Primary router for all security tasks. Routes to the right skill. |
| `bb-methodology` | 🆕 ★ | 5-phase hunting workflow orchestrator + critical thinking framework |
| `bug-bounty` | 🆕 ☆ | Complete pipeline index + tool orchestration (execution layer) |

## Category Routers (7)
| Skill | 标记 | Description |
|-------|------|-------------|
| `recon-for-sec` | ★ | Asset discovery, technology identification |
| `api-sec` | ★ | REST, GraphQL, mobile backend routing |
| `auth-sec` | ★ | Authentication, sessions, OAuth, JWT, authorization |
| `injection-checking` | ★ | XSS, SQLi, SSRF, XXE, SSTI, CMDi, NoSQL routing |
| `file-access-vuln` | ★ | Upload, download, LFI, path control |
| `business-logic-vuln` | ★ | Workflow abuse, race conditions, privilege escalation logic |
| `web2-vuln-classes` | 🆕 ☆ | 24 web2 bug classes deep reference (root cause + bypass + chains) |

## Deep Skills by Domain

### Web Security
| Skill | Description |
|-------|-------------|
| `xss-cross-site-scripting` | XSS playbook — HTML, attributes, JavaScript, DOM sinks |
| `sqli-sql-injection` | SQL injection — auth bypass, UNION, blind, out-of-band |
| `csrf-cross-site-request-forgery` | CSRF testing — state-changing flows, anti-CSRF defenses |
| `ssrf-server-side-request-forgery` | SSRF — URL fetching, hostname resolution, cloud metadata |
| `xxe-xml-external-entity` | XXE — XML, SVG, OOXML, SOAP, parser-driven imports |
| `cmdi-command-injection` | Command injection — shell metacharacters, blind, OOB |
| `ssti-server-side-template-injection` | SSTI — template expressions, server-side rendering |
| `nosql-injection` | NoSQL injection — MongoDB operators, JSON query objects |
| `cors-cross-origin-misconfiguration` | CORS misconfiguration testing |
| `csp-bypass-advanced` | Advanced CSP bypass techniques |
| `crlf-injection` | CRLF injection — HTTP response headers, log poisoning |
| `open-redirect` | Open redirect — URL parameters, form actions, JS sinks |
| `clickjacking` | Clickjacking — framing, frame busting, drag-and-drop |
| `websocket-security` | WebSocket — CSWSH, handshake flaws, tooling |
| `http-host-header-attacks` | Host header injection and routing abuse |
| `http-parameter-pollution` | HPP — duplicate query/body key parsing |
| `http2-specific-attacks` | HTTP/2 protocol-specific attacks |
| `request-smuggling` | HTTP request smuggling and desync |
| `web-cache-deception` | Web cache deception and poisoning |
| `waf-bypass-techniques` | Generic WAF bypass methodology |
| `dangling-markup-injection` | Dangling markup injection |
| `csv-formula-injection` | CSV/spreadsheet formula injection (DDE, Excel) |
| `prototype-pollution` | Prototype pollution — client-side and server-side |
| `prototype-pollution-advanced` | Advanced prototype pollution — RCE, gadgets |
| `race-condition` | Race condition and TOCTOU testing |
| `upload-insecure-files` | Insecure file upload testing |
| `path-traversal-lfi` | Path traversal and LFI |
| `email-header-injection` | Email header injection and spoofing |
| `xslt-injection` | XSLT injection — processor fingerprinting, SSRF |
| `type-juggling` | PHP type juggling and weak comparison bypass |
| `401-403-bypass-techniques` | 401/403 bypass — headers, method override, path fuzzing |
| `subdomain-takeover` | Subdomain takeover detection and exploitation |
| `dependency-confusion` | Package-manager dependency confusion |
| `dns-rebinding-attacks` | DNS rebinding attack playbook |

### Authentication & Authorization
| Skill | Description |
|-------|-------------|
| `authbypass-authentication-flaws` | Authentication bypass — login flows, password reset, MFA |
| `jwt-oauth-token-attacks` | JWT and OAuth token attacks |
| `api-auth-and-jwt-abuse` | API authentication and JWT abuse |
| `api-authorization-and-bola` | API authorization and BOLA testing |
| `idor-broken-object-authorization` | IDOR and broken object authorization |
| `oauth-oidc-misconfiguration` | OAuth and OIDC misconfiguration testing |
| `saml-sso-assertion-attacks` | SAML SSO assertion attacks |

### Recon & Methodology
| Skill | Description |
|-------|-------------|
| `recon-and-methodology` | Asset mapping, endpoint discovery, tech fingerprinting |
| `api-recon-and-docs` | API reconnaissance and documentation review |
| `graphql-and-hidden-parameters` | GraphQL introspection and hidden parameter discovery |
| `insecure-source-code-management` | Source control exposure (.git, .svn, .env, backups) |

### OS Privilege Escalation
| Skill | Description |
|-------|-------------|
| `linux-privilege-escalation` | Linux PE — SUID, capabilities, cron, kernel, sudo |
| `windows-privilege-escalation` | Windows PE — services, UAC, token abuse, DLL hijack |
| `linux-security-bypass` | Linux security bypass — rbash, AppArmor, seccomp, SELinux |
| `macos-security-bypass` | macOS security bypass — SIP, TCC, Gatekeeper, XProtect |

### Active Directory
| Skill | Description |
|-------|-------------|
| `active-directory-kerberos-attacks` | Kerberos attacks — AS-REP, Kerberoasting, delegation |
| `active-directory-acl-abuse` | AD ACL abuse — DACL, AdminSDHolder, ownership |
| `active-directory-certificate-services` | AD CS attacks — ESC1-ESC13 matrix |
| `ntlm-relay-coercion` | NTLM relay and coercion — PetitPotam, DFSCoerce |

### Lateral Movement & Pivoting
| Skill | Description |
|-------|-------------|
| `linux-lateral-movement` | Linux lateral movement — SSH, NFS, Kerberos, Docker |
| `windows-lateral-movement` | Windows lateral movement — PSRemoting, WMI, SMB, RDP |
| `tunneling-and-pivoting` | Tunneling and pivoting — SSH tunnels, port forwarding |
| `unauthorized-access-common-services` | Unauthorized access — Redis, Rsync, Docker, etc. |

### Binary Exploitation (Pwn)
| Skill | Description |
|-------|-------------|
| `stack-overflow-and-rop` | Stack overflow and ROP — buffer hijack, ret2libc, gadgets |
| `heap-exploitation` | Heap exploitation — ptmalloc2/glibc, tcache poisoning |
| `format-string-exploitation` | Format string exploitation |
| `arbitrary-write-to-rce` | Arbitrary write to RCE — GOT overwrite, FSOP, vtable |
| `kernel-exploitation` | Linux kernel exploitation |
| `sandbox-escape-techniques` | Sandbox escape — Python, Lua, seccomp, JS, WASM |

### Reverse Engineering
| Skill | Description |
|-------|-------------|
| `anti-debugging-techniques` | Anti-debugging detection and bypass |
| `code-obfuscation-deobfuscation` | Code obfuscation analysis and deobfuscation |
| `binary-protection-bypass` | Binary protection bypass — ASLR, PIE, NX, RELRO, CFI |
| `vm-and-bytecode-reverse` | Custom VM and bytecode reverse engineering |
| `symbolic-execution-tools` | Symbolic execution — angr, Z3, concolic execution |
| `browser-exploitation-v8` | Browser and V8 exploitation |
| `macos-process-injection` | macOS process injection |

### Cryptography
| Skill | Description |
|-------|-------------|
| `classical-cipher-analysis` | Classical ciphers — substitution, transposition, Vigenère |
| `hash-attack-techniques` | Hash attacks — length extension, MD5/SHA1 collisions |
| `rsa-attack-techniques` | RSA attacks — factorization, Coppersmith, Bleichenbacher |
| `lattice-crypto-attacks` | Lattice-based cryptanalysis — LLL, CVP, uSVP |
| `symmetric-cipher-attacks` | Symmetric cipher attacks — CBC bit-flip, padding oracle, ECB |
| `ghost-bits-cast-attack` | Java "Ghost Bits" / Cast Attack (Black Hat Asia 2026) |

### Mobile Security
| Skill | Description |
|-------|-------------|
| `android-pentesting-tricks` | Android pentesting — SSL pinning, Frida, Intent hijacking |
| `ios-pentesting-tricks` | iOS pentesting — keychain, jailbreak detection, URL schemes |
| `mobile-ssl-pinning-bypass` | Mobile SSL pinning bypass — Frida, Objection, Xposed |

### Container & Cloud
| Skill | Description |
|-------|-------------|
| `container-escape-techniques` | Container escape — Docker, LXC, Kubernetes pod escape |
| `kubernetes-pentesting` | Kubernetes pentesting — RBAC, pod breakout, secrets |

### Blockchain & Smart Contracts
| Skill | Description |
|-------|-------------|
| `defi-attack-patterns` | DeFi attacks — flash loans, price oracle, reentrancy |
| `smart-contract-vulnerabilities` | Smart contract auditing — Solidity/EVM |

### AI/ML Security
| Skill | Description |
|-------|-------------|
| `ai-ml-security` | AI/ML security — pickle RCE, model poisoning, adversarial |
| `llm-prompt-injection` | LLM prompt injection — direct, indirect, tool misuse |

### Network & Protocol
| Skill | Description |
|-------|-------------|
| `network-protocol-attacks` | Network protocol attacks — ARP, LLMNR, DHCP, IPv6 |
| `traffic-analysis-pcap` | Traffic analysis and PCAP forensics |

### Forensics & Other
| Skill | 标记 | Description |
|-------|------|-------------|
| `memory-forensics-volatility` | ★ | Memory forensics with Volatility 2/3 |
| `steganography-techniques` | ★ | Steganography detection and extraction |
| `reverse-shell-techniques` | ★ | Reverse shell — bash, PowerShell, Python, PHP, Rust |
| `windows-av-evasion` | ★ | AV/EDR evasion — AMSI, ETW, .NET assembly |
| `deserialization-insecure` | ★ | Insecure deserialization — Java, PHP, Python |
| `jndi-injection` | ★ | JNDI injection — Log4Shell, LDAP, RMI |
| `expression-language-injection` | ★ | EL injection — Java EL, SpEL, OGNL, MVEL |
| `business-logic-vulnerabilities` | ★ | Business logic — workflows, coupons, race conditions |

---

## 🆕 CBB Workflow Skills (14 — 执行层)

> 详见 `FUSION_ROUTES.md` 了解每个 CBB Skill 与原始 Skill 的协作关系

### Workflow Orchestration
| Skill | 标记 | Description |
|-------|------|-------------|
| `bb-methodology` | 🆕 ★ | 5-phase hunting mindset + decision flow. Start here for any session. |
| `bug-bounty` | 🆕 ☆ | Complete pipeline: recon→hunt→validate→report. Tool orchestration layer. |
| `web2-recon` | 🆕 ★ | Automated recon pipeline: subfinder/httpx/katana/nuclei |
| `web2-vuln-classes` | 🆕 ☆ | 24 bug classes deep reference. Companion to authoritative deep skills. |
| `triage-validation` | 🆕 ★ | 7-Question Gate + 4 pre-submission gates. Kill weak findings fast. |
| `report-writing` | 🆕 ★ | H1/Bugcrowd/Intigriti/Immunefi report templates + CVSS 3.1 |
| `security-arsenal` | 🆕 ☆ | Quick-reference methodology cheatsheet. Companion, not standalone. |

### Unique Specializations (CBB 独有)
| Skill | 标记 | Description |
|-------|------|-------------|
| `cicd-security` | 🆕 ★ | CI/CD pipeline: GitHub Actions injection, OIDC theft, supply chain |
| `credential-attack` | 🆕 ★ | Password spray methodology: wordlist-gen → breach-check → spray |
| `graphql-audit` | 🆕 ★ | GraphQL security: introspection, batching, IDOR via aliasing |
| `meme-coin-audit` | 🆕 ★ | Token/rug-pull audit: 8 token bug classes, EVM + Solana |
| `mobile-pentest` | 🆕 ★ | Mobile app pentest: APK/IPA → proxy → API testing |
| `web3-audit` | 🆕 ★ | Smart contract audit: 10 DeFi bug classes, Foundry PoC template |
| `miniapp-recon` | 🆕 ★ | Mini program asset discovery: WeChat/Alipay/Douyin AppID→wxapkg→API endpoints |

### Commands (29 — Slash Commands)
| Command | Description |
|---------|-------------|
| `/recon` | Automated recon pipeline |
| `/hunt` | Active vulnerability hunt |
| `/autopilot` | Full autonomous hunt loop |
| `/validate` | Validate findings (7-Question Gate) |
| `/report` | Generate professional report |
| `/bypass-403` | 401/403 bypass techniques |
| `/scan-cves` | CVE intelligence scan |
| `/cloud-recon` | Cloud asset discovery |
| `/param-discover` | Hidden parameter discovery |
| `/secrets-hunt` | Git secret scanning |
| `/takeover` | Subdomain takeover check |
| `/web3-audit` | Smart contract audit |
| `/token-scan` | Token security scan |
| `/spray` | Password spray orchestration |
| `/wordlist-gen` | Company-specific wordlist generation |
| `/osint-employees` | Employee name/email gathering |
| `/breach-check` | HIBP password breach check |
| `/chain` | Exploit chain builder |
| `/intel` | Threat intelligence lookup |
| `/scope` | Scope verification |
| `/surface` | Attack surface analysis |
| `/pickup` | Resume previous session |
| `/remember` | Save to hunt memory |
| `/memory-gc` | Memory garbage collection |
| `/triage` | Quick finding triage |
| `/arsenal` | External tool arsenal |
| `/graphql-audit` | GraphQL audit (alias) |
| `/miniapp-recon` | Mini program asset discovery |
| `/certstream-watch` | Real-time SSL certificate monitoring (seconds-level) |
| `/github-watch` | Real-time GitHub commit monitoring (pre-release assets) |
| `/scope-aggregate` | Multi-platform scope pull |

### Agents (10 — AI Agents)
| Agent | Model | Purpose |
|-------|-------|---------|
| `autopilot` | sonnet | Full autonomous hunt loop |
| `recon-agent` | haiku | Subdomain enumeration + live host discovery |
| `recon-ranker` | sonnet | Attack surface prioritization |
| `validator` | opus | 7-Question Gate finding validation |
| `report-writer` | opus | Professional report generation |
| `chain-builder` | sonnet | A→B→C exploit chain discovery |
| `web3-auditor` | opus | Smart contract security audit |
| `token-auditor` | haiku | Fast token/rug-pull security check |
| `credential-hunter` | sonnet | Autonomous credential attack pipeline |

---

> **维护**: 新增 Skill 后同时更新本 INDEX 和 `FUSION_ROUTES.md`。CBB Skill 更新通过 `~/scripts/sync-cbb-tools.sh` 同步。
