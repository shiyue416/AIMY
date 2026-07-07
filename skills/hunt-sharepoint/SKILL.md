---
name: hunt-sharepoint
description: Hunt Microsoft SharePoint Server (2013/2016/2019/Subscription Edition) on-prem farms — anonymous endpoint enumeration, version disclosure, legacy SOAP login bypass (Authentication.asmx), ToolShell precondition chain (CVE-2025-53770), SafeControl reflection enumeration via Picker.aspx, NTLM Type-2 AD topology disclosure. Use when target has SharePoint headers (SPRequestGuid, X-MS-InvokeApp) or paths (/_layouts/15/, /_vti_bin/).
sources: github, authorized-engagement
report_count: 1
---

# HUNT-SHAREPOINT — SharePoint On-Prem Security

## Crown Jewel Targets
1. **SP2013 EoL** — every CVE after April 2023 permanently unpatched
2. **CVE-2025-53770 "ToolShell"** — ToolPane.aspx + anonymous FormDigest + unencrypted ViewState
3. **Authentication.asmx** — legacy SOAP login, no rate limit, anonymous
4. **NTLM Type-2 leak** — internal AD forest/disclosure
5. **SafeControl reflection** — Picker.aspx type enumeration

## Attack Surface Signals
```
SPRequestGuid, X-MS-InvokeApp, MicrosoftSharePointTeamServices headers
/_layouts/15/  /_vti_bin/  /_api/  /_catalogs/
Set-Cookie: FedAuth=    (claims auth)
Set-Cookie: ASP.NET_SessionId=  
```

## Phase 1 — Version & Surface Enum
```bash
# Version from header
curl -sI "https://$TARGET/_layouts/15/start.aspx" | grep -i "MicrosoftSharePointTeamServices"

# Anonymous REST API
curl -s "https://$TARGET/_api/web" | head -5

# Legacy SOAP services
curl -s "https://$TARGET/_vti_bin/Authentication.asmx" | grep -i "Login\|LoginResult"
```

## Phase 2 — ToolShell (CVE-2025-53770) Precondition
```bash
# Check if ToolPane.aspx is anonymous-reachable
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit"

# Check if FormDigest is issued anonymously
curl -s -X POST "https://$TARGET/_api/contextinfo" -H "Content-Length: 0" \
  | grep -oP 'FormDigestValue":"[^"]+"'

# Check ViewState encryption
curl -s "https://$TARGET/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  | grep -oP '__VIEWSTATEENCRYPTED" value="[^"]*"'
```

## Phase 3 — Authentication.asmx Legacy Login
```bash
# SOAP Login request — anonymous
curl -s -X POST "https://$TARGET/_vti_bin/Authentication.asmx" \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://schemas.microsoft.com/sharepoint/soap/Login" \
  -d '<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <Login xmlns="http://schemas.microsoft.com/sharepoint/soap/">
        <username>USER</username>
        <password>PASS</password>
      </Login>
    </soap:Body>
  </soap:Envelope>'

# Response contains ErrorCode (0=success) + Cookie
```

## Phase 4 — SafeControl Enumeration
```bash
# Picker.aspx exists?
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.WebControls.UnsecuredLayoutsPicker"

# Type enum via error diff
for type in "UnsecuredLayoutsPicker" "FieldValueControl" "UserControl" "SerializableWebPart"; do
  echo "$type: $(curl -s "https://$TARGET/_layouts/15/Picker.aspx?PickerDialogType=$type" | grep -c "PickerDialog")"
done
```

## Bypass Techniques
| Defense | Bypass |
|---|---|
| Forms auth on branded login | Authentication.asmx SOAP bypass |
| ViewState encrypted | Recover keys from web.config leak |
| Claims auth (FedAuth) | Check if rtFa cookie is validate-able |
| SP2019+ patched | SP2013 same code path → no patch ever |

## Chain Table
| Finding | Impact |
|---------|--------|
| ToolShell precondition (3 checks pass) | Critical — chain to RCE |
| Authentication.asmx anonymous | High — brute force AD accounts |
| SP2013 farm reachable | High — permanently unpatched |
| NTLM Type-2 leak | Medium — AD recon |
| SafeControl enumeration | Medium — enabler |
| _api/web anonymous | Medium — info disclosure |

## Related Skills
- **hunt-aspnet** — ViewState deserialization fundamentals
- **hunt-ntlm-info** — NTLM Type-2 capture
- **hunt-rce** — full exploit after precondition chain
- **triage-validation** — 7-Question Gate
