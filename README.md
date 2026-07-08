# AIMY v3.0 — AI Bug Bounty Hunting Framework

<p align="center">
  <b>180+ attack skills &middot; 120+ Python detectors &middot; 3,000+ H1 reports &middot; 50,000 WooYun cases</b><br>
  <sub>Four-source fusion architecture — HackSkills · Anthropic · src-hunter · Mingxi injection</sub>
</p>

---

## Quick Start

```bash
git clone https://github.com/shiyue416/AIMY.git
cd AIMY
cp .env.example .env          # fill in your API keys
pip install -r aimy/requirements.txt
python aimy.py
```

## Architecture

```
aimy/                    Python framework (120+ detectors, 7-phase pipeline)
skills/                  180 attack methodology skills
anthropic-skills/        8,946 defense/forensics/compliance skills
references/              5,891 reference files (H1 reports, payloads, playbooks)
├── hackerone-reports/    3,029 disclosed H1 reports (indexed by vuln class)
├── payload-kit/          52 specialized payload collections
└── playbooks/            68 attack playbooks
mingxi-injection/         Role injection layer (Hook + Rules)
mappings/                 MITRE ATT&CK / NIST CSF / OWASP
benchmarks/               XBOW 104-target detection baseline
```

## Coverage

| Category | Count | Source |
|----------|-------|--------|
| Attack skills | 180 | HackSkills (April) + custom |
| Defense skills | 8,946 | Anthropic Cybersecurity |
| Python detectors | 120+ | Custom (BaseDetector template) |
| H1 reports (indexed) | 3,029 | hackerone-reports-bug-bounty |
| WooYun archives | 50,000 | Public vulnerability database |
| Benchmark targets | 104 | XBOW (91/104 pass rate) |

## Pipeline — 7-Phase Hunt Workflow

```
Phase 1  Intake     scope validation, rule loading, timebox
Phase 2  Recon      6-dimension passive recon (zero packets sent)
Phase 3  Enum       active probing (rate-limited)
Phase 4  Hunt       signal→playbook→tool 3-level dispatch
Phase 5  Validate   7-question gate + 4 acceptance gates
Phase 6  Report     template-driven, compliance-checked
Phase 7  Flywheel   technique recording, skill auto-upgrade
```

## Usage

```bash
/recon target.com              # Phase 2: 6-dimension passive recon
/hunt target.com               # Phase 3-4: active hunt
/validate                      # Phase 5: 7-question verification gate
/report                        # Phase 6: generate submission-ready report

# Specialized
/security-research ctf|vuln|pentest|audit|ir
/secrets-hunt --github-org target
/cloud-recon --keyword target
```

## Skills — Auto-Load Rule

Every skill has a trigger table. When the AI detects a matching keyword, the skill loads automatically before any payload is generated. **No payload from memory — everything from files.**

| Trigger | Skill Loaded |
|---------|-------------|
| SSRF / url= / webhook / callback | `ssrf-server-side-request-forgery/SKILL.md` |
| SQLi / id= / union / select / sleep | `sqli-sql-injection/SKILL.md` |
| XSS / q= / search / innerHTML | `xss-cross-site-scripting/SKILL.md` |
| IDOR / /api/user/ / 越权 | `idor-broken-object-authorization/SKILL.md` |
| SSTI / template / {{ / jinja / twig | `ssti-server-side-template-injection/SKILL.md` |
| ... | 35+ more triggers |

## Safety Constraints (Iron Rules)

| Rule | Detail |
|------|--------|
| Rate limit | ≤1 req/s, ≤500 req/day, max 5 concurrent |
| Data safety | ≤3 user records to confirm, stop immediately |
| Scope only | Pre-flight confirmation before any active request |
| No destruction | Read-only verification (id/whoami/uname only) |
| No secrets in code | All keys via env vars, abort if missing |
| Circuit breaker | >10 consecutive errors → auto-pause 5 min |

## Comparison — GitHub Red-Line Systems (14 projects surveyed)

| Project | Score | Highlight |
|---------|-------|-----------|
| **AIMY (this)** | 45/50 | Concrete rate limits, data caps, PII formats, CTF/SRC mode switch |
| pentest-agents (H-mmer) | 30/50 | 42-line never-submit chain table, env var missing abort |
| Claude-BugHunter (elementalsouls) | 28/50 | CFAA declaration, supply chain prohibition, 7-Question Gate |

## Documentation

| File | Purpose |
|------|---------|
| [SKILL.md](./SKILL.md) | Fusion-router (53KB, 542 lines) — 4-source unified dispatch |
| [INDEX.md](./INDEX.md) | Complete skill index with cross-references |
| [QUICKSTART.md](./QUICKSTART.md) | Step-by-step setup and first hunt |
| [CLAUDE.md](./CLAUDE.md) | Agent identity, conventions, tech stack |

## Related

- [src-hunter-skill](https://github.com/MyuriKanao/src-hunter-skill) — SRC workflow methodology
- [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) — 71-skill BB + red-team bundle
- [pentest-agents](https://github.com/H-mmer/pentest-agents) — Multi-agent hunting framework
