# 通用方法论 — 卡壳兜底 & 攻击优先级

> 视角: Phase 4 所有信号走完、仍然没找到漏洞时的备选方案。
> Phase 3 资产过了一遍 playbook 仍然没命中? 翻这里。

---

## 1. 攻击优先级 (先打什么)

```
P0 (Critical):    SSRF → RCE → 大规模数据泄露
                  • SSRF 可打内网/metadata/云服务 → 赏金最高
                  • RCE 单洞 = 十个低危总和

P1 (High):        认证绕过 → Stored/Blind XSS
                  • 认证绕过解锁更多功能 → 扩大攻击面
                  • Stored XSS 影响所有访问用户

P2 (Medium):      IDOR → SQLi → 业务逻辑
                  • IDOR 容易出且稳定
                  • 业务逻辑: 支付/优惠券/订单操作

P3 (Low):         CSRF → 信息泄露 → 配置问题
                  • 不报反射 XSS / Open Redirect / 信息泄露
                  • 不报缺少安全头 / SPF / DMARC
```

---

## 2. 信号走完后的兜底 (8 条路)

### 2.1 时光机考古

```bash
# WayBack Machine 翻旧版
curl "https://web.archive.org/cdx/search/cdx?url=*.target.com&output=json" | jq '.[][2]' | sort -u

# gau 找历史 URL
gau target.com | grep -E '\.js$|\.json$|\.xml$|api|admin|debug'
```

### 2.2 非对称思维 (业务逻辑)

```
常规思维:      用户A不能看用户B的数据
非对称思维:   用户A创建订单后,用相同参数重放 → 双倍积分?
              优惠券叠加? 负值数量? 小数精度?

常规思维:      登录需要密码
非对称思维:   忘记密码的 Token 是不是可预测?
              OAuth 登录后能不能通过 redirect_uri 偷 code?
```

### 2.3 参数突变

```
所有你试过的端点,换参数格式重测一遍:

  数字 → UUID:          /api/user/1 → /api/user/550e8400-e29b-...
  UUID → 数字:         /api/user/uuid → /api/user/1
  ID → Hash:           /api/order/1 → /api/order/e3b0c44298fc1c...
  数组 → 对象:          ?ids=1 → ?ids[]=1
  JSON → form:          Content-Type: application/json → form-data
  GET → POST:           ?id=1 → POST body id=1
```

### 2.4 多步流程漏洞

```
找业务流程,不是单端点:

  注册 → 登录 → 修改资料 → 删除账号 (每一步都可能越权)
  下单 → 支付 → 取消 → 退款 (每一步都可能逻辑缺陷)
  创建 → 审核 → 发布 → 删除 (权限逐级检查)
```

### 2.5 竞态窗口

```
限速/限量/抢购/抽奖/投票/关注 → 并发打:

  python main.py race-condition <URL>
  # 或 Burp: http_race 同时发 N 个请求
```

### 2.6 JS/前端线索

```
翻 JS 找:
  ☐ 硬编码的 API Token / 密钥
  ☐ 隐藏的 API 端点 (/internal, /admin, /debug)
  ☐ 功能开关 (feature_flags, enable_xxx)
  ☐ 注释里的 TODO / FIXME / 测试账号
  ☐ WebSocket 连接 → 找未鉴权的实时通道

工具: gau/katana/xnLinkFinder + source-map 还原
```

### 2.7 越权绕过 (当 403 拦你时)

```
☐ HTTP 方法切换: GET→POST→PUT→PATCH→OPTIONS
☐ Header 添加: X-Forwarded-For: 127.0.0.1, X-Real-IP: 127.0.0.1
☐ 路径遍历: /admin → /./admin → //admin → /admin/
☐ 大小写混淆: /Admin → /ADMIN → /aDmIn
☐ URL 编码: /%61dmin → /a%64min
☐ Header 注入: X-Original-URL: /admin, X-Rewrite-URL: /admin
☐ 协议降级: HTTPS→HTTP
```

### 2.8 换技术栈视角

```
目标技术栈 → 对应的特定漏洞:

  Java (Spring):    Actuator 泄露 / SpEL 注入 / 反序列化
  PHP (Laravel):    .env 泄露 / Debug 模式 / 反序列化
  Node.js (Express): 原型链污染 / 路径遍历 / 未授权 API
  Python (Django):  SECRET_KEY 泄露 / Pickle 反序列化 / Debug 模式
  Go:               参数绑定漏洞 / 模板未转义
  .NET:             反序列化 (ViewState) / 路径遍历 / SSRF
```

---

## 3. 输出 checklist

```
☐ 六维侦察走完? (零发包)
☐ 活资产矩阵建好? (端口/服务/指纹)
☐ 每个入口信号都测了? (对照信号→playbook 表)
☐ 卡壳兜底 8 条路走了至少 3 条?
☐ 时间盒没超?
```

---

## 参考文献

- `references/SRC_终极脑洞.md` — 时光机考古 + 非对称思维
- `references/业务逻辑拓展骚思路.md` — 7 种非对称思维
- `彦的h1飞轮/05_举一反三机制.md` — 成功技法变体应用
- `skills/` — 对应漏洞类的完整 SKILL.md
