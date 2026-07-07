---
name: hunt-tls-network
description: Hunt TLS/Network protocol vulnerabilities — TLS version downgrade, weak cipher acceptance (3DES, RC4, CBC mode), certificate validation bypass, HSTS bypass via subdomain, STARTTLS injection, ALPN downgrade, OCSP stapling misconfiguration, plaintext protocol fallback. Use when target exposes HTTPS, SMTP, IMAP, POP3, or FTP over TLS.
sources: hackerone_public, tls_research
report_count: 0
---

# HUNT-TLS-NETWORK — TLS/Network Protocol Testing

## Crown Jewel Targets
- **TLS 1.0 / 1.1 enabled** — protocol downgrade → POODLE/BEAST class attacks
- **Weak cipher suites** — 3DES, RC4, CBC-mode ciphers
- **Certificate validation bypass** — client does not verify cert chain
- **HSTS bypass via subdomain** — root domain has HSTS but subdomain doesn't
- **STARTTLS injection** — command injection before TLS handshake
- **ALPN downgrade** — h2 → http/1.1 forced downgrade

## Phase 1 — TLS Configuration Scan
```bash
# Using testssl.sh (most comprehensive)
git clone --depth 1 https://github.com/drwetter/testssl.sh
./testssl.sh --quiet --protocols $TARGET:443
./testssl.sh --quiet --cipher-per-proto $TARGET:443
./testssl.sh --quiet --headers $TARGET:443

# Quick scan with nmap
nmap --script ssl-enum-ciphers -p 443 $TARGET

# Check for TLS 1.0/1.1
openssl s_client -connect $TARGET:443 -tls1 2>/dev/null | grep "Protocol.*TLSv1"
openssl s_client -connect $TARGET:443 -tls1_1 2>/dev/null | grep "Protocol.*TLSv1.1"
```

## Phase 2 — Certificate Inspection
```bash
# Full cert details
openssl s_client -connect $TARGET:443 -showcerts 2>/dev/null | openssl x509 -text -noout

# Check for weak signature algorithm
openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -text | grep "Signature Algorithm"

# OCSP stapling check
openssl s_client -connect $TARGET:443 -status 2>/dev/null | grep "OCSP Response Status"
```

## Phase 3 — HSTS & Protocol Downgrade
```bash
# Check HSTS header
curl -sI "https://$TARGET/" | grep -i "strict-transport-security"

# Test subdomain for missing HSTS
curl -sI "https://sub.$TARGET/" | grep -i "strict-transport-security"

# Test ALPN downgrade
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN"
```

## Related Skills
- **hunt-grpc** — gRPC requires h2 ALPN
- **triage-validation** — most TLS findings are informational only
