---
name: mid-engagement-ir-detection
description: Methodology for detecting client SOC patches, attacker activity, and security-state changes that occur DURING a red-team engagement. Use when running active engagement against a monitored target, a confirmed finding stops reproducing, baseline timing shifts, or response patterns change during testing. NOT for bug bounty (client doesn't know you're there).
sources: authorized-engagement
report_count: 1
---

# MID-ENGAGEMENT-IR-DETECTION — SOC Awareness During Red Team

## Core Insight
In a red-team engagement against a competent SOC, the target security state changes during your test. These changes are:
1. **Valuable findings** (positive IR observations)
2. **Confirmation evidence** (mid-engagement patch = original vuln was real)
3. **Classification signals** (WAF rule vs code fix — different remediation depth)

## Pre-Test Baseline Capture
```python
fingerprint = {
    "ts": time.time(),
    "baseline_response_time_ms": <measure>,
    "baseline_response_size_bytes": <measure>,
    "response_headers": <capture set>,
    "waf_cookies": <list>,
    "lockout_count": <known>,
    "known_good_endpoints": <list of (path, status, size)>,
}
```

## Detection Signals

### SOC is Watching (Blue Team Triggered)
```
- Previously working payload returns 403/406 suddenly
- New WAF cookie appears (e.g., __cf_bm, ak_bmsc)
- Response time doubles (WAF inspection overhead)
- Session gets consistently blocked after first trigger
```

### Vulnerability Confirmed by Patch
```
- Finding worked yesterday → today returns 200 with no payload effect
- Same endpoint, same params, different behavior
- Response size changes by >5% on that specific path only
```

### External Attacker Activity
```
- Lockout count jumps unexpectedly  
- Unusual error rate on authentication endpoints
- Credentials that worked stop working
- New accounts locked that you didn't touch
```

## Response Protocol
```
1. Document pre-change evidence immediately (screenshots, curl dumps)
2. Note exact timestamp of behavior change
3. If finding stops reproducing: still report the original finding (pre-change evidence)
4. If external attacker detected: inform engagement lead
5. Add IR observation as separate finding: "SOC Response Time: X minutes"
```

## Related Skills
- **triage-validation** — 7-Question Gate for pre-change evidence
- **evidence-hygiene** — document before/after properly
