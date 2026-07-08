# Quick Start — First Hunt in 5 Minutes

> Prerequisites: Python 3.10+, Git, an LLM API key (GPT-5.5 or compatible).
> This guide assumes the **bounty** scene (read-only, prove-then-stop). For pentest/redteam, see [Mode Reference](#modes).

---

## 0. Install & Configure

```bash
git clone https://github.com/shiyue416/AIMY.git && cd AIMY
pip install -r aimy/requirements.txt
cp .env.example .env
# Edit .env → set GPT5_API_KEY=sk-xxx (required)
```

## 1. Verify

```bash
python aimy.py --list-providers    # confirm LLM is reachable
python -m aimy.memory.session_brief  # read this week's top techniques
```

## 2. First Hunt

```bash
# Full pipeline (recon → hunt → validate → report)
/recon target.com
/hunt target.com
/validate
/report
```

Or use the single-command entry:

```bash
python aimy.py --target target.com
```

---

## Decision Table — Which Command When

| You want to... | Command |
|---------------|---------|
| Find all subdomains + assets (zero packets to target) | `/recon target.com` |
| Hunt for a specific vuln class | `/hunt target.com --vuln-class ssrf` |
| Exhaustively hunt ALL 26 vuln classes | `/hunt target.com --autonomous` |
| Verify a finding before reporting | `/validate` |
| Generate a submission-ready report | `/report` |
| Score a finding for bounty-worthiness | `/report bounty` |
| Resume an interrupted hunt | `/resume target.com` |
| Check engagement status | `/status` |

---

## Signal → Skill Routing Table

When you see these signals on a target, the corresponding skill auto-loads. No need to manually trigger.

| Signal | Auto-Loaded Skill | First Payload |
|--------|-------------------|---------------|
| `?url=` `?redirect=` `?callback=` `?webhook=` | `ssrf-server-side-request-forgery` | `http://interactsh-server/` |
| `?id=` `?user=` `/api/user/1` numeric IDs | `idor-broken-object-authorization` | Increment ID by 1 |
| `?q=` `?search=` input reflected in HTML | `xss-cross-site-scripting` | `<img src=x onerror=alert(1)>` |
| `?file=` `?page=` `?path=` `../` in URL | `path-traversal-lfi` | `../../../etc/passwd` |
| SQL error: "syntax error" "unclosed quote" | `sqli-sql-injection` | `' OR '1'='1` |
| `{{` `{%` in response, "template" in error | `ssti-server-side-template-injection` | `{{7*7}}` |
| JWT in Cookie/Header (`eyJ...`) | `jwt-oauth-token-attacks` | alg:none |
| `cmd=` `exec=` `ping=` `shell=` | `cmdi-command-injection` | `; id` |
| XML body, SVG upload, `<!DOCTYPE` | `xxe-xml-external-entity` | `<!DOCTYPE x [<!ENTITY ...>` |
| 403/401 on admin endpoints | `401-403-bypass-techniques` | Header override chain |
| Payment form, coupon code, order flow | `business-logic-vulnerabilities` | Negative price, race checkout |
| `__proto__` `constructor` in JSON | `prototype-pollution` | `{"__proto__":{"isAdmin":true}}` |
| `Access-Control-Allow-Origin` header | `cors-cross-origin-misconfiguration` | Origin: attacker.com |

---

## Modes

### Runtime Mode

| Mode | Trigger | Behavior |
|------|---------|----------|
| Veteran (default) | `AIMY_MODE=veteran` | Filters low-value vulns, concise output |
| Rookie | `AIMY_MODE=rookie` | Full explanation, remediation advice, no filter |

### Scene Mode

| Scene | Trigger | Read-Only | Goal |
|-------|---------|-----------|------|
| Bounty (default) | `AIMY_SCENE=bounty` | ✅ | Find reportable vulns, stop at proof |
| Pentest | `AIMY_SCENE=pentest` | ❌ | Full engagement deliverable |
| Red Team | `AIMY_SCENE=redteam` | ❌ | Kill-chain, stealth, persistence |
| Auto-Pentest | `AIMY_SCENE=auto-pentest` | ❌ | Autonomous end-to-end |

---

## Safety Gates (Always Active)

Every request passes through the Safety Gate before execution:

| Gate | Rule |
|------|------|
| Rate | ≤1 req/s, ≤500/day, max 5 concurrent |
| Scope | Only authorized domains — pre-flight confirmation required |
| Data | ≤3 user records to confirm, stop immediately on leak |
| No-Destroy | Read-only (`id`/`whoami`/`uname`), no file write/delete |
| No-Evade | No CAPTCHA bypass, no MFA bypass |
| Circuit | >10 errors → auto-pause 5 min |

---

## Phase Gates — Hunt Checklist

Each phase must pass its exit gate before proceeding.

```
Phase 1  □ Scope validated       □ Timebox set        □ Rules loaded
Phase 2  □ ≥3/6 recon dims       □ Asset list built   □ Tech stack fingerprinted
Phase 3  □ Port scan done        □ WAF identified     □ Parameter map built
Phase 4  □ All signals triaged   □ Each vuln class ≥1 test  □ Evidence saved
Phase 5  □ 8Q passed             □ 4G passed          □ Validator confirmed
Phase 6  □ PII redacted          □ PoC reproducible   □ CVSS scored
Phase 7  □ Technique recorded    □ Session brief refreshed
```

---

## Verification — 8-Question Gate

Before submitting, every finding must answer these:

| Q | Question | Fail Action |
|---|----------|-------------|
| Q1 | Can an attacker reproduce it step-by-step? | Reject |
| Q2 | Is the impact in the program's accepted list? | Reject |
| Q3 | Is the root cause on an in-scope asset? | Reject |
| Q4 | Does it require impossible privileges? | Reject |
| Q5 | Is this already known/accepted behavior? | Reject |
| Q6 | Can you prove actual business impact? | Downgrade |
| Q7 | Is it in the never-submit list? | Reject |
| Q8 | Does it reproduce with a different session? | Reject |

Never-submit list: `self-XSS | reflected XSS (no impact) | open redirect | missing security headers | version disclosure | SPF/DMARC | CORS (no credentials)`

---

## Reporting

```bash
# Generate report for all confirmed findings
/report

# Bounty platform format (H1/Bugcrowd/Intigriti)
/report bounty

# Pentest deliverable format
/report pentest
```

Report template:
```
Title:    [Vuln Type] in [Endpoint] allows [Attacker] to [Impact]
CVSS 4.0: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/...
Steps:    curl -v 'https://target.com/...'
Evidence: HTTP request/response + screenshot
Impact:   Business-level description
```

PII must be redacted: phone `138******12`, email `te***@example.com`, token first 2 + last 2 chars.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| subfinder rate-limited | Use crt.sh fallback: `curl -s "https://crt.sh/?q=%25.target.com&output=json"` |
| httpx all timeout | Try `--timeout 5`, test one with curl manually |
| WAF blocking | Read `skills/waf-bypass-techniques/SKILL.md` → encoding ladder |
| No JS found (SPA) | Use playwright engine: `python aimy/tools/playwright_engine.py` |
| Stuck — no findings | Swap model: `python aimy.py -p claude -t target.com` |
| Got rate-limited (429) | Pause 5 min, circuit breaker auto-engages |
| Got blocked (503) | Pause 10 min, check scope, reduce concurrency |

---

## Reference

| Document | Purpose |
|----------|---------|
| [README.md](./README.md) | Full architecture, modes, skill table, safety rules |
| [SKILL.md](./SKILL.md) | Fusion-router — 4-source dispatch (1,033 lines) |
| [INDEX.md](./INDEX.md) | Complete skill index with cross-references |
| [CLAUDE.md](./CLAUDE.md) | Agent identity, conventions, priorities |
