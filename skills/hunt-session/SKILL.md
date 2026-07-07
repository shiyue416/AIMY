---
name: hunt-session
description: Hunt session management vulnerabilities — predictable session tokens, session fixation, concurrent session limits, session timeout misconfiguration, session token in URL, JWTs not invalidated on logout, session replay after password change, session token leaked in referer or logs. Use when analyzing authentication and session handling.
sources: hackerone_public, portswigger_research
report_count: 0
---

# HUNT-SESSION — Session Management Vulnerabilities

## Crown Jewel Targets
- **JWT not invalidated on logout** — no server-side session tracking
- **Session not invalidated on password change** — old session still valid
- **Predictable session tokens** — sequential, timestamp-based
- **Session timeout > 24 hours** — no inactivity timeout
- **Session token in URL** — referer header leak to third-party

## Phase 1 — Session Token Analysis
```bash
# Check session token format
curl -sI "https://$TARGET/login" | grep -i "set-cookie"

# Session not invalidated on logout
curl -s -b "session=SESSION_A" "https://$TARGET/dashboard"
curl -s -X POST -b "session=SESSION_A" "https://$TARGET/logout"
curl -s -b "session=SESSION_A" "https://$TARGET/dashboard"  # should 401

# Session not invalidated on password change
curl -s -b "session=A" -X PUT "https://$TARGET/api/user/password" -d '{"password":"newpass"}'
curl -s -b "session=A" "https://$TARGET/dashboard"  # should 401
```

## Phase 2 — Session Fixation
```bash
# Set session before login, then use after login
curl -s -b "session=FIXED_TOKEN" "https://$TARGET/login"
curl -s -b "session=FIXED_TOKEN" -X POST "https://$TARGET/login" -d "user=x&pass=y"
# If FIXED_TOKEN is still valid after login → fixation exists
```

## Phase 3 — Session Token Predictability
```bash
# Capture N sequential tokens
for i in $(seq 1 20); do
  curl -sI "https://$TARGET/login" | grep "set-cookie" >> tokens.txt
done
# Analyze pattern: numeric, timestamp, hash
```

## Related Skills
- **hunt-ato** — session bugs chain to ATO
- **triage-validation** — 7-Question Gate
