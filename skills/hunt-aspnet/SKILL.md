---
name: hunt-aspnet
description: Hunt ASP.NET-specific surface — ViewState deserialization (signed-only vs encrypted), machineKey recovery, dual-parser MAC-bypass anti-pattern, request-validator bypass, trace.axd/elmah.axd disclosure, load-balanced ViewState cross-node failures, SafeControl enumeration via reflection, customErrors mode=Off stack-trace leaks, classic Webforms .aspx/.asmx/.svc surface. Built for ASP.NET Webforms + WCF + SharePoint farms.
sources: github, authorized-engagement
report_count: 1
---

## Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**
- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error and look for `Version Information` in the error body.
2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`.
3. **Check `__VIEWSTATEENCRYPTED` value.** Empty = signed-only but NOT encrypted.
4. **Test ViewState parser-error differential** — 7+ payload shapes to detect dual-parser anti-pattern.
5. **Look for load-balanced cross-node ViewState MAC failures.**
6. **Probe `trace.axd` and `elmah.axd`.**
7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex`.
8. **Test request-validator bypass.** Entity-encoded, JSON/XML POST, Cookie/Referer.
9. **Check `customErrors` mode.** Stack traces = `mode="Off"`.
10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau`.
11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint`.
12. **SafeControl enumeration via reflection.**

---

## Payload & Detection Patterns

```bash
# Stack-trace fingerprint (stale ViewState POST)
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
```

```python
# ViewState parser-error differential probe
import requests, re
S = requests.Session(); S.verify = False
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR.*value="([^"]+)', r.text).group(1)

for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    print(f"  [{label:14s}] {r.status_code}")
```

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty | Recover decryption + validation keys from source-code leak / config disclosure |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename |
| `EnableViewStateMac="true"` | Recover `validationKey` from web.config disclosure |
| `trace.axd` localhost-only | X-Forwarded-For: 127.0.0.1 |
| WCF 401 on anonymous | Try `?wsdl` and `?mex` first |
| Telerik upload patched | Check Telerik version for older chains |
| `customErrors mode="On"` | Force different error path |

---

## Gate 0 Validation

1. **What can attacker do right now?** — trace.axd 200 = Critical, elmah.axd 200 = High
2. **Full chain or just primitive?** — signed-only without key recovery = Low
3. **Reproducible in <10 min?** — copy-pasteable curl/Python

---

## Real Impact Examples

### Scenario A — Signed-only ViewState on SharePoint 2013
`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. ViewState signed-only, FormDigest issued anonymously. CVE-2025-53770 precondition chain. **Critical**.

### Scenario B — Telerik RadAsyncUpload exposed
Telerik 2016.3.1027. CVE-2017-11317 keys are public. Upload → RCE. **Critical**.

### Scenario C — trace.axd + elmah.axd on HR portal
Bearer tokens in trace dump + connection string in error log. **Critical**.

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization RCE + ysoserial.net gadget chain
- **`hunt-sharepoint`** — SharePoint-specific RCE paths (ToolShell, SafeControl)
- **`hunt-ntlm-info`** — NTLM challenge capture → AD topology
- **`hunt-file-upload`** — Telerik/Umbraco/DNN upload handler RCE
- **`triage-validation`** — 7-Question Gate before submission
