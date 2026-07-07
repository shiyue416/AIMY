# SRC 挖洞终极脑洞：99%的人想不到的攻击面（2025-2026）

## 一、时光机考古学 -- 被遗忘接口才是金矿

1.1 Wayback Machine 逆向挖掘
  curl "https://web.archive.org/cdx/search/cdx?url=target.com/robots.txt&output=text"
  翻2020-2022年老版本 robots.txt,新版干干净净旧版全是宝

1.2 Gau + Katana 隐藏用法
  gau --subs target.com | grep -E '\.(json|php|aspx|jsp|do|action)$'
  旧版技术栈残骸,新团队接手后旧版没关干净 = 漏洞温床

## 二、HTTP 差异分析 -- 协议级降维打击

2.1 HTTP/1.1 vs HTTP/2 解析差异
  CDN接受H2,后端用H1.1 -> 请求走私 重复Host头混淆

2.2 Recursive Request Exploit (RRE) -- DEF CON 33 首发
  从输出反向溯源: video.m3u8 -> manifest.json -> stream API -> 认证服务
  谁没鉴权?谁没限速?

## 三、跨接口参数喂食 -- 参数注入

  接口A的参数整串强行拼到接口B后面
  GET /api/internal/config?limit=1&xxxid=100
  后端函数共享,前端没传但后端一直在等隐藏参数

  变种参数: limit=-1 pageSize=10000 userId= uid= debug=true admin=true role=admin

## 四、小程序隐藏攻击面

4.1 云开发密钥硬编码
  反编译wxapkg -> grep env/secret/token/key -> 接管云数据库

4.2 sessionKey泄露 -> 任意用户伪造登录
  小程序登录接口返回sessionKey -> 解密用户手机号

4.3 小程序码scene参数注入
  修改scene参数 -> 越权访问其他用户数据

## 五、APP逆向 -- 客户端不可信

5.1 SO文件逆向
  strings libcore.so | grep -i "key|secret|aes|des|rsa|token"

5.2 Hook绕过四件套
  证书锁定绕过/Root检测绕过/生物识别绕过/动态代码加载

## 六、Blind/OOB漏洞 -- 扫描器永远找不到

6.1 异步工作流SSRF -- 2026最大蓝海
  文件上传(SVG/PDF) -> URL导入配置 -> webhook地址填写
  注入OOB payload -> 后台几小时/几天后处理 -> DNS回调到达

6.2 OOB检测工具栈: Interactsh / Burp Collaborator

## 七、AI/LLM基础设施 -- 2026全新攻击面

7.1 ClawJacked: WebSocket跨源劫持 -> 完全控制本地AI Agent
7.2 Open WebUI SSRF: IPv6映射地址绕过 ::ffff:169.254.169.254
7.3 AI代理密钥泄露: OPENAI_API_KEY/ANTHROPIC_API_KEY
7.4 RAG系统SSRF: prompt注入引导LLM访问云元数据

## 八、HTTP重定向凭据泄露

  客户端访问http://user:pass@target.com/api -> 302跳转到攻击者域名
  -> 客户端自动把Authorization发到攻击者服务器

## 九、CI/CD供应链投毒

9.1 GitHub Actions恶意YAML注入 via pull_request_target
9.2 package.json preinstall注入
9.3 Actions Cache Poisoning

## 十、UUID/ID逆向工程 -- 看起来随机但其实不随机

  收集10-20个ID -> 分析哪些字节会变 -> 如果和时间相关 -> 可以预测
  工具: Turbointruder + Burp Comparer

## 十一、十一条核心心法

1. 新版删了不等于后端停用 -- Wayback Machine翻旧版
2. 接口参数可以跨界注入 -- A接口的参数喂给B接口
3. HTTP/1.1 != HTTP/2 -- 差异就是漏洞
4. 小程序云密钥写在JS里 = 白给
5. .so里的字符串什么都有 -- strings是你的好朋友
6. 盲漏洞需要OOB信道 -- 没有Interactsh等于没测
7. AI本地服务监听localhost != 安全 -- WebSocket跨源直连
8. 302跳转会带走Authorization头
9. 开源项目不是代码,是漏洞清单 -- 搜别人的fix commit
10. 看起来随机的ID往往不随机 -- 时间戳+固定格式
11. 子公司 >> 收购品牌 >> 海外站 >> 主站
