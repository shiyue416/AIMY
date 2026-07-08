# AIMY v3.0 — AI Bug Bounty Hunting Framework

<p align="center">
  <strong>180+ attack skills &middot; 120+ Python detectors &middot; 3,000+ H1 reports &middot; 50,000 WooYun cases</strong><br>
  
  <sub>7-phase hunt pipeline · 35 trigger-keyword auto-load · 14-project r
</p>

---

## Quick Start

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
cp .env.example .env          # fill in your API keys (see Configuration below)
pip install -r aimy/requirements.txt

# Start hunting
python aimy.py                              # interactive mode
python aimy.py --target example.com         # targeted hunt
python aimy.py -q "hunt example.com"        # single query
```

---

## Usage — Step by Step

### Step 1: Install

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
pip install -r aimy/requirements.txt
```

### Step 2: Configure

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```ini
GPT5_API_KEY=sk-your-api-key-here   # required — LLM provider
```

Optional extras:

```ini
AIMY_MODE=veteran               # veteran (default, high-value only) | rookie (full output)
AIMY_SCENE=bounty               # bounty (default) | pentest | redteam | auto-pentest
H1_USERNAME=your_h1_username    # for HackerOne flywheel sync
H1_TOKEN=your_h1_token          # for HackerOne flywheel sync
BURP_MCP_TOKEN=your_token       # for Burp Suite integration
```

### Step 3: Verify setup

```bash
python aimy.py --list-providers    # confirm LLM is reachable
python -m aimy.memory.session_brief # read this week's top techniques (optional)
```

### Step 4: Start hunting

```bash
# Interactive mode — type commands directly
python aimy.py

# One-shot — single query
python aimy.py -q "hunt example.com for ssrf"

# Targeted — full pipeline on one domain
python aimy.py --target example.com
```

### Step 5: Run the 7-phase pipeline

```bash
/recon target.com       # Phase 2 — passive recon (zero packets to target)
/hunt target.com        # Phase 3+4 — active probing + vulnerability hunting
/hunt target.com --vuln-class sqli   # Phase 4 — focus on one vuln class
/hunt target.com --autonomous        # Phase 4 — exhaustive (26 classes, ≥25 attempts each)
/validate               # Phase 5 — 8-question verification gate
/report                 # Phase 6 — generate submission-ready report
/report bounty          # Phase 6 — H1/Bugcrowd/Intigriti format
```

### Step 6: Interpret results

| Output | Meaning |
|--------|---------|
| `[vuln] Confirmed: SSRF in /api/proxy` | Verified finding — ready to report |
| `[warn] Downgraded: reflected XSS → informatory` | Validated but low impact — skip (in veteran mode) |
| `[reject] Rejected by Validator (Q3: out-of-scope)` | Failed verification gate — do NOT report |
| `No signal on /api/...` | Endpoint tested, nothing found — move on |

### Step 7: Repeat & improve

```bash
# Run the flywheel — learns from your findings
python aimy.py --flywheel

# Check updated technique rankings
python -m aimy.memory.session_brief

# Start next hunt with updated knowledge
python aimy.py --target next-target.com
```

---

## Modes

AIMY has two runtime modes and four scene modes, controlled by environment variables.

### Runtime Mode

| Mode | Env | Behavior |
|------|-----|----------|
| **Veteran** (default) | `AIMY_MODE=veteran` | High-value vulns only. Auto-filters `reflected_xss \| open_redirect \| info_disclosure \| low \| info \| information`. Concise output. |
| **Rookie** | `AIMY_MODE=rookie` | Full output with explanations + remediation advice. No severity filter. |

### Scene Mode

| Scene | `AIMY_SCENE=` | Goal | Key Difference |
|-------|--------------|------|----------------|
| **Bounty** (default) | `bounty` | Find high-bounty vulns for SRC/H1 | Read-only, prove-then-stop, ≤3 user records max |
| **Pentest** | `pentest` | Full engagement deliverable | Post-exploit chains, lateral movement, evidence collection |
| **Red Team** | `redteam` | Simulated adversary | Kill-chain focus, stealth, persistence evaluation |
| **Auto-Pentest** | `auto-pentest` | Autonomous end-to-end | No human-in-the-loop, exhaustive coverage contract |

```bash
# Example: rookie mode + bounty scene
AIMY_MODE=rookie AIMY_SCENE=bounty python aimy.py --target target.com

# Example: veteran mode + auto-pentest
AIMY_MODE=veteran AIMY_SCENE=auto-pentest python aimy.py --target target.com --autonomous
```

---

## Architecture

```
aimy/                          Python framework
├── core/                      Orchestrator, ReAct loop, state machine, bus
├── tools/                     120+ vulnerability detectors (BaseDetector template)
│   ├── ssrf_detector.py       SSRF with OOB/interactsh integration
│   ├── sqli_blind.py          Boolean/time-based blind SQLi
│   ├── xss_detector.py        Reflected/Stored/DOM XSS with browser verification
│   ├── ssti_detector.py       SSTI with 20+ template engines
│   ├── jwt_detector.py        JWT alg:none, weak secret, kid injection
│   ├── race_condition.py      TOCTOU with parallel request engine
│   ├── deser_weaponizer.py    Java/Python/PHP deserialization gadget chains
│   └── ...                    115+ more detectors
├── memory/                    Flywheel: FeedbackDB, EVX evolution engine, session_brief
├── llm/                       Multi-provider LLM client (GPT-5.5, LongCat, Claude)
├── safety/                    Safety gate, scope validator, audit trail
├── skills/                    Skill loader, registry, router, formatter
├── references/                Reference loader (keyword-indexed, on-demand)
└── telemetry/                 (Removed — merged into memory/flywheel.py)

skills/                        180 attack methodology skills
├── ssrf-server-side-request-forgery/    SKILL.md + SCENARIOS.md + BYPASS.md
├── sqli-sql-injection/                  SKILL.md + BLIND.md + OOB.md + UNION.md
├── xss-cross-site-scripting/            SKILL.md + DOM.md + CSP_BYPASS.md
└── ...                                  176 more skill directories

anthropic-skills/              8,946 defense/forensics/compliance skills
references/                    5,891 reference files
├── hackerone-reports/          3,029 disclosed H1 reports (indexed by vuln class)
├── payload-kit/                52 specialized payload collections
├── playbooks/                  68 attack playbooks
└── nuclei-templates-ai/        Auto-generated Nuclei templates
```

---

## Usage — 7-Phase Hunt Pipeline

Every hunt follows a deterministic 7-phase workflow. Each phase has entry/exit gates.

### Phase 1: Intake (5 min)

Scope validation, rule loading, timebox setting.

```bash
# AI-driven intake
/recon target.com          # triggers Phase 1→2

# Manual scope check
python aimy.py --target target.com --scope-only
```

### Phase 2: Recon — 6-Dimension Passive

**Zero packets sent to target.** All data from third-party sources.

| Dimension | Source | Coverage |
|-----------|--------|----------|
| 1. Subdomain passive | crt.sh, Chaos, subfinder, amass (-passive) | 85-92% |
| 2. Permutation mutation | dnsgen (suffix), alterx (NLP word-segment) | 1→50x multiplier |
| 3. Favicon correlation | mmh3 hash → FOFA icon_hash / Shodan http.favicon | Cross-asset discovery |
| 4. ASN/IP reverse | asnmap, amass intel, bgp.he.net, RADB whois | Network-level correlation |
| 5. CSP intelligence | CSP header parsing → trusted domain list → httpx liveness | Free subdomains |
| 6. JS sourcemap | .js.map → source-map-unpack → TS source → endpoints + creds | Source-level attack surface |

```bash
/recon target.com                           # all 6 dimensions
/favicon-hunt --url https://target.com      # dimension 3 only
/asn-discovery --org "Target Corp"          # dimension 4 only
/csp-intel --url https://target.com         # dimension 5 only
/js-sourcemap --recon-dir recon/target.com  # dimension 6 only
```

### Phase 3: Enum — Active Probing

Rate-limited active enumeration with safety pre-checks.

```bash
/hunt target.com              # triggers Phase 3→4
/hunt target.com --vuln-class ssrf   # focus on one class
```

### Phase 4: Hunt — Signal→Playbook→Tool Dispatch

Three-level dispatch engine:

1. **Signal detection** — parameter names, HTTP headers, response patterns
2. **Playbook selection** — maps signal to specific skill+tool
3. **Tool execution** — runs the Python detector with the right payload

```bash
# Targeted hunting
/hunt target.com --vuln-class idor
/hunt target.com --vuln-class sqli
/hunt target.com --vuln-class ssti

# Autonomous (exhaustive — 26 vuln classes, ≥25 attempts/class, ≥90 min)
/hunt target.com --autonomous
```

### Phase 5: Validate — 8-Question Gate + 4 Acceptance Gates

Every finding must pass:

| Q# | Question | Fail = |
|----|----------|--------|
| Q1 | Is there actual impact? | Reject |
| Q2 | Is the impact type in the program's accepted list? | Reject |
| Q3 | Is the root cause on an in-scope asset? | Reject |
| Q4 | Can it be reproduced consistently? | Reject |
| Q5 | Is there a more severe exploitation path? | Upgrade |
| Q6 | Are all PII redacted in evidence? | Fix |
| Q7 | Does it violate any red-line rule? | Reject |
| Q8 | Is this a duplicate? | Dedup |

4 Acceptance Gates: evidence completeness, impact authenticity, compliance, anonymization.

```bash
/validate           # runs the 8-question gate
```

### Phase 6: Report — Template-Driven

Generates submission-ready reports with:
- Vulnerability overview
- Technical analysis (root cause, trigger condition, attack surface)
- Reproduction steps / PoC
- Impact assessment
- Remediation suggestions

```bash
/report             # generate report for all confirmed findings
/report bounty      # bounty-platform format (H1/Bugcrowd/Intigriti)
/report pentest     # pentest deliverable format
```

### Phase 7: Flywheel — Auto-Evolution

Records technique outcomes, triggers skill upgrades, refreshes session brief.

```bash
# Manual flywheel run
python -m aimy.memory.flywheel

# Read this week's top techniques
python -m aimy.memory.session_brief
```

---

## Skill Auto-Load System

Every vulnerability class has a trigger table. When the AI detects a matching keyword in the user's input or the target's response, the corresponding skill loads **before any payload is generated**.

**Hard constraint: no payload from training memory — everything from skill files.**

| Trigger Keywords | Skill Loaded |
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

## Safety Constraints (Iron Rules)

Violating any of these → immediate stop, no exceptions.

### Rate Limiting

| Constraint | Value |
|------------|-------|
| Max request rate | **1 req/s** (interval ≥1 second) |
| Daily quota (same target) | **500 requests/day** |
| Max concurrency | **5** |
| curl flags (built-in) | `--max-time 10 --limit-rate 100K` |
| Circuit breaker | >10 consecutive errors → auto-pause **5 minutes** |

### Attack Scope

- ✅ Only in-scope assets
- ✅ Only user-authorized domains (confirmed per-session)
- ✅ Pre-flight output before any active action: target URL + request count + expected impact → wait for confirmation
- ❌ No out-of-scope domain requests
- ❌ No internal network/port scanning
- ❌ No unauthorized subdomain scanning

### Data Safety

| Rule | Limit |
|------|-------|
| User data to confirm | **≤3 records**, stop immediately |
| On data leak discovery | **Stop immediately**, do not expand |
| User data storage | **Never** store locally |
| PII in PoC | **Redacted** (first 2 + last 2 chars, or SHA256 fingerprint) |

### Prohibited Actions

- ❌ DoS / concurrency >5 / infinite loops / infinite recursion
- ❌ Modify/delete/overwrite data
- ❌ Scan internal network ports/services
- ❌ Upload webshell to production
- ❌ Build/distribute attack tools (exploit framework / C2 / malware)
- ❌ Supply chain poisoning (NPM/PyPI/GitHub Actions injection)
- ❌ Bypass CAPTCHA / human verification
- ❌ Bypass MFA/2FA
- ❌ Brute-force real user accounts
- ❌ Use public DNSLog platforms (must use vendor platform or self-hosted interactsh)
- ❌ Guess/substitute/hardcode when env vars missing (must abort)

### Compliance

- All testing within SRC-authorized scope
- Notify first after discovering vulnerabilities, do not exploit privately
- Report includes testing methodology and tools
- Comply with target country/region cybersecurity laws (CFAA / Computer Misuse Act / Cybersecurity Law)
- All API keys/tokens via environment variables — **never hardcoded**
- Missing required env vars → abort, no assumptions

---

## Configuration (.env)

```bash
# Required
GPT5_API_KEY=sk-xxx                    # LLM provider (GPT-5.5 or compatible)

# Optional — HackerOne API
H1_USERNAME=your_username
H1_TOKEN=your_token

# Optional — Burp Suite MCP integration
BURP_MCP_TOKEN=your_burp_token
BURP_MCP_HOST=127.0.0.1
BURP_MCP_PORT=9444

# Optional — Alternative LLM
LONGCAT_API_KEY=ak_xxx                 # LongCat-2.0 (1.6T MoE, 1M context)

# Mode
AIMY_MODE=veteran                      # veteran | rookie
AIMY_SCENE=bounty                      # bounty | pentest | redteam | auto-pentest
AIMY_TELEMETRY_ENABLED=false           # internal quality tracking (silent)
```

---

## Agent System — Specialized Hunters

AIMY spawns specialized sub-agents for different vulnerability classes:

| Agent | Focus | Key Tools |
|-------|-------|-----------|
| `ssrf-hunter` | SSRF detection | OOB + interactsh + bypasses |
| `sqli-hunter` | SQL injection | Boolean, time, error, OOB |
| `xss-hunter` | XSS | Reflected, stored, DOM-based |
| `idor-hunter` | IDOR/BOLA | Object-level authorization |
| `rce-hunter` | RCE | SSTI, deserialization, CMDi, XXE |
| `validator` | Deterministic verification | curl-based True/False + 8-Question Gate |
| `coordinator` | Multi-agent orchestration | Parallel hunting dispatch |

---

## Documentation Map

| File | Purpose | Lines |
|------|---------|-------|
| [README.md](./README.md) | This file — overview, usage, modes, safety | ~300 |
| [SKILL.md](./SKILL.md) | Fusion-router — 4-source dispatch table (53KB) | 1,033 |
| [INDEX.md](./INDEX.md) | Complete skill index with cross-references | ~600 |
| [QUICKSTART.md](./QUICKSTART.md) | Step-by-step hunt manual with checklists | 751 |
| [CLAUDE.md](./CLAUDE.md) | Agent identity, conventions, tech stack, priorities | ~400 |

## License

MIT — see individual skill files for their respective licenses.
