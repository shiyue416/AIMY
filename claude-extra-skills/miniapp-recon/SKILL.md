---
name: miniapp-recon
description: >-
  小程序资产发现——微信/支付宝/抖音小程序AppID收集、wxapkg/apkg解包、
  API端点提取、云开发资源发现、第三方服务域名提取。国内SRC挖洞必备第七维度，
  填补传统Web六维法对小程序攻击面零覆盖的空白。被动优先（AppID搜索零发包）
  → 运行时提取（代理抓包·解包）→ 静态分析（端点·凭据·云资源）→ 存活验证。
  Use when targeting Chinese internet companies (Meituan/ByteDance/Tencent/etc.)
  or whenever the target has WeChat/Alipay/Douyin mini programs in scope.
---

# 小程序资产发现 (Mini Program Asset Discovery)

> **定位**: 国内SRC挖洞的第七维度。传统六维法（子域名/排列/图标/ASN/CSP/JS）对小程序攻击面零覆盖。
> **适用**: 美团·字节·腾讯·阿里·百度·京东·拼多多等一切有小程序的中国互联网公司。
> **产出**: AppID清单→API端点→云资源→第三方服务→直接喂给 Phase 4 漏洞探测。

---

## 核心原则：被动优先 → 运行时提取 → 静态分析

```
Phase 1: AppID 被动收集 (零发包到目标·纯第三方数据源)
  → 微信搜一搜 · Web JS 源码 · GitHub/码云 · 第三方商店 · crt.sh
Phase 2: 小程序包获取 (主动·需微信/支付宝客户端)
  → mitmproxy + Proxifier · .wxapkg 定位 · unveilr 解包
Phase 3: 静态分析 (本地·无网络请求)
  → API端点 · 云函数 · 云数据库 · AppSecret · WebSocket · 第三方域名
Phase 4: 存活验证 (主动·httpx探测)
  → 提取的API端点验证 · 云环境ID收集
```

---

## Phase 1: AppID 被动收集（零发包）

### 1.1 微信搜一搜关键词

```bash
# 第三方小程序商店爬取
# 阿拉丁指数 https://www.aldzs.com/
# 知晓程序 https://minapp.com/
curl -s "https://api.minapp.com/search?q=美团" | jq '.data[].app_id'
```

### 1.2 从目标 Web JS 源码提取 AppID

**这是最高ROI的被动方法**——目标网站如果集成了微信JS-SDK，AppID直接写在JS里：

```bash
TARGET="meituan.com"
RECON_DIR="recon/$TARGET"

# 从已有JS文件搜索微信小程序AppID
grep -rPn 'wx\.config|weixin-js-sdk|wx[a-f0-9]{16}' "$RECON_DIR/js/" 2>/dev/null

# 搜索支付宝小程序AppID
grep -rPn 'my\.getAuthCode|alipay-js-sdk' "$RECON_DIR/js/" 2>/dev/null

# 搜索抖音小程序AppID
grep -rPn 'tt\.login|bytedance-js-sdk' "$RECON_DIR/js/" 2>/dev/null

# 更宽泛的AppID模式
grep -rPn 'appId|app_id|AppID|miniProgram|miniprogram' \
  "$RECON_DIR/js/" 2>/dev/null | grep -v 'node_modules'

# 目标主页内联JS
curl -s "https://$TARGET" | grep -oP '(wx[a-f0-9]{16}|wxdefine|wx\.config|miniProgram)'

# 通用AppID正则 (微信AppID格式: wx + 16位十六进制)
curl -s "https://$TARGET" | grep -oP 'wx[a-f0-9]{16}'
```

**常见AppID出现位置**:
```
- <script> 中的 wx.config({ appId: 'wx...' })
- JS bundle 中的 __wxConfig
- import 语句中的 @/config/wechat
- <meta> 标签中的 wx:app_id
- JSON 配置中的 "wechat_app_id"
```

### 1.3 GitHub/码云 搜索

```bash
# GitHub 搜索 (第三方·零发包到目标)
gh search code "meituan wx appid" --language javascript 2>/dev/null
gh search code "meituan miniprogram" --language javascript 2>/dev/null
```

### 1.4 crt.sh 中小程序相关域名

```bash
TARGET="meituan.com"

# 小程序云开发专用域名
curl -s "https://crt.sh/?q=%25.wxapp.tc.qq.com&output=json" | jq -r '.[].name_value' | grep "$TARGET"

# 微信云托管域名
curl -s "https://crt.sh/?q=%25.tcloudbase.com&output=json" | jq -r '.[].name_value' | grep "$TARGET"

# 支付宝小程序相关域名
curl -s "https://crt.sh/?q=%25.alipayobjects.com&output=json" | jq -r '.[].name_value' | grep "$TARGET"
```

---

## Phase 2: 小程序包获取（主动·需要客户端）

### ⚠️ 安全声明
```
本阶段涉及主动请求和本地文件操作。需要:
  1. --active --scope <scope.txt> --yes 三参数
  2. 微信/支付宝客户端仅用于抓自己的小程序包
  3. 不解包非目标公司的小程序
  4. 提取的AppSecret不离开本地
```

### 2.1 代理配置

```bash
# mitmproxy 设置（推荐）
mitmproxy --listen-port 8080 --mode regular

# 微信 Windows 客户端代理
# 设置 → 通用设置 → 代理设置 → 手动
# 地址: 127.0.0.1 端口: 8080

# Proxifier 配置（微信不走系统代理时需要）
# Profile → Proxy Servers → Add
# Address: 127.0.0.1 Port: 8080 Protocol: HTTPS
# Proxification Rules → wechat.exe → 走代理
```

### 2.2 .wxapkg 文件定位

```bash
# Windows 微信客户端缓存位置
WECHAT_CACHE="$APPDATA/Tencent/WeChat/Radium/Applet"

# macOS
WECHAT_CACHE="$HOME/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data"

# 找到目标小程序的包文件
find "$WECHAT_CACHE" -name "*.wxapkg" -mtime -1 2>/dev/null

# 按大小过滤（真实业务小程序通常 > 500KB）
find "$WECHAT_CACHE" -name "*.wxapkg" -size +500k 2>/dev/null

# 按时间排序——最近打开的最可能是目标
find "$WECHAT_CACHE" -name "*.wxapkg" -printf '%T+ %p\n' 2>/dev/null | sort -r | head -20
```

### 2.3 解包

```bash
# unveilr (推荐·Node.js·活跃维护)
npm install -g unveilr
unveilr /path/to/小程序.wxapkg -o mini_source/

# wxappUnpacker (Python·老牌稳定)
git clone https://github.com/xuedingmiaojun/wxappUnpacker.git
pip install -r requirements.txt
python wuWxapkg.py /path/to/小程序.wxapkg
```

解包后结构：
```
mini_source/
├── app-config.json      # 全局配置（AppID/名称/版本/权限）
├── app-service.js       # 业务逻辑（主要分析目标）
├── page-frame.html      # 页面框架
├── pages/               # 各页面源码
│   ├── index/
│   │   ├── index.js     # 页面逻辑 + API调用
│   │   ├── index.wxml   # 页面模板
│   │   └── index.wxss   # 页面样式
│   └── ...
├── utils/               # 工具函数
└── app.wxss             # 全局样式
```

---

## Phase 3: 静态分析

### 3.1 API 端点提取

```bash
SOURCE_DIR="mini_source"

# 微信小程序 — wx.request 调用
grep -rPn "wx\.request\s*\(" "$SOURCE_DIR" \
  | grep -oP 'url\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > endpoints_wx.txt

# 支付宝小程序 — my.request 调用
grep -rPn "my\.request\s*\(" "$SOURCE_DIR" \
  | grep -oP 'url\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > endpoints_alipay.txt

# 通用 fetch/axios
grep -rPn -E "(fetch|axios\.get|axios\.post|axios\.put|axios\.delete)\s*\(" "$SOURCE_DIR" \
  | grep -oP '(url\s*:\s*)?["\x27]\Khttps?://[^"\x27]+' \
  | sort -u > endpoints_http.txt

# WebSocket 连接
grep -rPn "wx\.connectSocket\s*\(" "$SOURCE_DIR" \
  | grep -oP 'url\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > ws_endpoints.txt

# 提取的域名汇总
cat endpoints_*.txt | grep -oP 'https?://\K[^/]+' | sort -u > api_domains.txt

echo "[+] API 端点: $(wc -l < endpoints_http.txt)"
echo "[+] 唯一域名: $(wc -l < api_domains.txt)"
```

### 3.2 云开发资源提取

```bash
# 微信云开发 — 云函数
grep -rPn "wx\.cloud\.callFunction\s*\(" "$SOURCE_DIR" \
  | grep -oP 'name\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > cloud_functions.txt

# 云数据库集合
grep -rPn "db\.collection\s*\(" "$SOURCE_DIR" \
  | grep -oP '["\x27]\K[^"\x27]+' \
  | sort -u > cloud_collections.txt

# 云存储路径
grep -rPn "wx\.cloud\.uploadFile|wx\.cloud\.downloadFile|wx\.cloud\.getTempFileURL" "$SOURCE_DIR" \
  | grep -oP 'cloudPath\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > cloud_storage.txt

# 云环境 ID (高价值 — 可能可以外部调用)
grep -rPn "wx\.cloud\.init\s*\(" "$SOURCE_DIR" \
  | grep -oP 'env\s*:\s*["\x27]\K[^"\x27]+' \
  | sort -u > cloud_env_ids.txt
```

### 3.3 硬编码凭据 & 敏感信息

```bash
# AppSecret / API Key / Token (高价值发现)
grep -rPn -E "(appSecret|app_secret|AppSecret|APP_SECRET)\s*[:=]\s*[\x27\"]" "$SOURCE_DIR"

# 各类 Key
grep -rPn -E "(apiKey|api_key|secretKey|secret_key|accessKey|accessToken|access_token)\s*[:=]\s*[\x27\"]" "$SOURCE_DIR"

# 微信支付相关（极高敏感）
grep -rPn -E "(mch_id|mch_key|partner_key|paySignKey|apiclient_cert)" "$SOURCE_DIR"

# 第三方服务 Key (Sentry/Firebase等)
grep -rPn -E "(sentry\.io|sentry_dsn|firebase|bugly|bugsnag)" "$SOURCE_DIR" \
  | grep -oP 'https://[^"'\''\s]+' \
  | sort -u > third_party_services.txt

# 内网地址泄漏
grep -rPn -E "(10\.\d{1,3}|172\.1[6-9]|172\.2\d|172\.3[0-1]|192\.168\.)\." "$SOURCE_DIR" \
  | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?' \
  | sort -u > internal_ips.txt
```

### 3.4 权限 & 配置分析

```bash
# app-config.json 中的权限声明
jq '.permission' "$SOURCE_DIR/app-config.json" 2>/dev/null

# 插件列表（插件可能有自己的攻击面）
jq '.plugins' "$SOURCE_DIR/app-config.json" 2>/dev/null

# 分包配置（分包 = 额外的业务逻辑模块）
jq '.subPackages' "$SOURCE_DIR/app-config.json" 2>/dev/null

# 需要授权的敏感接口
jq '.requiredPrivateInfos' "$SOURCE_DIR/app-config.json" 2>/dev/null
```

---

## Phase 4: 存活验证

```bash
# 用提取的 API 端点做 httpx 存活验证
if _have httpx; then
  cat endpoints_http.txt | httpx -silent -status-code -title -tech-detect \
    -o api_live.txt 2>/dev/null
  echo "[+] 存活 API: $(wc -l < api_live.txt)"
fi

# 对提取的新域名做子域名发现（回补六维管线）
if [ -s api_domains.txt ]; then
  while read -r domain; do
    [ -z "$domain" ] && continue
    if ! grep -qF "$domain" "$RECON_DIR/subdomains/all.txt" 2>/dev/null; then
      echo "[→] 新发现域名: $domain → 回补到六维管线"
      echo "$domain" >> "$RECON_DIR/subdomains/miniapp_discovered.txt"
    fi
  done < api_domains.txt
fi
```

---

## 产出文件结构

```
findings/miniapp/<timestamp>/
├── appids_wechat.txt         # 微信小程序AppID清单
├── appids_alipay.txt         # 支付宝小程序AppID清单
├── appids_douyin.txt         # 抖音小程序AppID清单
├── mini_source/              # 解包后的源码（如果有）
├── endpoints_http.txt        # 提取的API端点
├── endpoints_ws.txt          # WebSocket端点
├── api_domains.txt           # API域名（回补六维）
├── cloud_functions.txt       # 云函数名
├── cloud_collections.txt     # 云数据库集合
├── cloud_env_ids.txt         # 云环境ID
├── secrets_potential.txt     # 疑似凭据（需人工确认）
├── third_party_services.txt  # 第三方服务
├── internal_ips.txt          # 内网IP引用
└── api_live.txt              # 存活API验证
```

---

## 下一步路由

| 发现 | 下一步 |
|------|--------|
| 大量API端点 | → `api-sec` → `api-authorization-and-bola` (IDOR测试) |
| 支付相关端点 | → `business-logic-vulnerabilities` (支付逻辑) |
| 云环境ID | → `cloud-recon` (云资源扩展) |
| 新域名发现 | → `web2-recon` (回补六维管线) |
| 硬编码AppSecret | → `/validate` (关键发现·直接验证) |
| 内网地址 | → `ssrf-server-side-request-forgery` (SSRF探测内网) |
| 第三方服务Key | → `/secrets-hunt` (凭据泄露扩展) |

---

## 安全约束

```
✅ 被动阶段: 零发包到目标·纯第三方数据源
⚠️ 主动阶段: 需要 --active --scope --yes 三参数
❌ 不解包非目标公司的小程序
❌ 不提取后传播AppSecret
❌ 不修改小程序代码后重新打包
✅ 所有敏感输出本地存储·不上传
```

---

## 与其他维度的关系

```
┌──────────────────────────────────────────────┐
│         小程序资产发现 —— 第七维度              │
│                                              │
│  输入:                                        │
│    ← 六维Web管线 (提供JS文件/域名用于AppID提取) │
│    ← 微信/支付宝客户端 (提供wxapkg)            │
│                                              │
│  输出:                                        │
│    → 六维Web管线 (回补新发现的API域名)          │
│    → Phase 4 漏洞探测 (API端点直接喂给hunt.py) │
│    → credential-attack (硬编码凭据)            │
│    → ssrf-* (内网地址)                        │
│                                              │
│  互补维度:                                    │
│    + mobile-pentest (App+小程序双端覆盖)       │
│    + api-recon-and-docs (API端点文档化)       │
│    + cloud-recon (云资源交叉验证)              │
└──────────────────────────────────────────────┘
```
