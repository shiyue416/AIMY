#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ChainSuggest -- 漏洞危害提升 + 拓展思路引擎."""

from __future__ import annotations
import random

CHAIN_UPGRADE = {
    "xss": [
        ("XSS->CSRF->ATO", "XSS+CSRF->ATO", "medium", "critical"),
        ("XSS->cache poison", "XSS payload被CDN缓存", "medium", "critical"),
    ],
    "ssrf": [
        ("SSRF->cloud metadata->IAM", "SSRF访问cloud metadata->IAM凭证", "high", "critical"),
        ("SSRF->Redis->RCE", "SSRF通过gopher://写crontab->RCE", "high", "critical"),
        ("SSRF->DNS Rebinding", "SSRF用DNS rebinding绕过IP白名单", "high", "critical"),
    ],
    "sqli": [
        ("SQLi->OUTFILE->RCE", "MySQL INTO OUTFILE写webshell->RCE", "high", "critical"),
        ("SQLi->xp_cmdshell->RCE", "MSSQL通过xp_cmdshell执行系统命令", "high", "critical"),
    ],
    "idor": [
        ("IDOR->批量泄露", "遍历ID参数->大量用户数据泄露", "high", "critical"),
        ("IDOR->提权", "IDOR修改role字段->管理员权限", "high", "critical"),
    ],
    "lfi": [
        ("LFI->log poison->RCE", "LFI读access.log->User-Agent注PHP->RCE", "high", "critical"),
    ],
    "xxe": [
        ("XXE->SSRF", "XXE通过SYSTEM entity发内网请求", "high", "critical"),
    ],
    "cmdi": [
        ("CMDi->reverse shell", "bash reverse shell->完全控制服务器", "critical", "critical"),
    ],
    "csrf": [
        ("CSRF->ATO", "CSRF修改邮箱/密码->账号接管", "medium", "critical"),
    ],
    "ssti": [
        ("SSTI->RCE", "模板引擎执行系统命令->RCE", "high", "critical"),
    ],
    "jwt": [
        ("JWT alg=none", "JWT修改alg为none->伪造任意用户", "high", "critical"),
    ],
    "graphql": [
        ("GQL内省->IDOR", "内省发现隐藏字段->越权查询", "medium", "high"),
    ],
    "race condition": [
        ("竞态->双重支付", "并行请求同一扣款->余额无限", "high", "critical"),
    ],
    "open redirect": [
        ("OR+OAuth->ATO", "Open redirect劫持OAuth授权码->账号接管", "low", "critical"),
    ],
}

LATERAL_EXPANSION = {
    "ssrf": [
        "试试gopher:// -- 不只http://, gopher能打Redis/SMTP/MySQL",
        "DNS Rebinding(TTL=0) -- 绕过严格IP白名单",
        "URL解析器差异绕过 -- #@ \\@ %00@ IPv6-mapped IPv4",
        "PDF/截图生成器SSRF -- 嵌入<iframe>/<img>读内网",
    ],
    "xss": [
        "试试DOM clobbering -- <a id=xxx>覆盖全局变量",
        "mXSS(突变XSS) -- <noscript><p title=...</noscript>",
        "JSONP端点利用 -- 找同源JSONP做CSP bypass",
        "postMessage监听器 -- addEventListener未校验origin",
    ],
    "sqli": [
        "试试ORDER BY注入 -- CASE WHEN...THEN...ELSE...END",
        "NoSQL注入 -- MongoDB $where/$ne/$regex",
        "二次注入 -- 存一次无害数据->另一处拼入SQL时触发",
    ],
    "idor": [
        "参数类型转换 -- id=123 -> id[]=123 (PHP数组绕过)",
        "GraphQL node()接口 -- query{node(id:...)}",
        "WebSocket IDOR -- WS消息ID常忘校验",
        "批量赋权 -- PATCH传{\"role\":\"admin\"}",
    ],
    "lfi": [
        "试试php://filter链 -- 多个filter组合读完整源码",
        "Windows日志投毒 -- access.log+UA shell",
    ],
    "xxe": [
        "试试Blind XXE -- 带外OOB通过参数实体",
        "SVG上传XXE -- <svg><!DOCTYPE svg[...]>",
        "XLSX/DOCX XXE -- Office文件解压后修改xml",
    ],
    "jwt": [
        "试试kid注入 -- kid:../../../etc/passwd",
        "jku注入 -- jku:https://attacker.com/evil-jwks.json",
        "算法混淆 -- RS256->HS256用公钥签名",
    ],
    "graphql": [
        "试试aliased查询 -- 用别名绕过对象级限制",
        "深度递归 -- query嵌套10000层(DoS)",
        "批量请求 -- 单请求包含多个mutation绕过速率",
    ],
    "business logic": [
        "撤销不等回滚:取消订单后券退回但限用计数器是否回滚",
        "退款精度攻击:退2.9件退290元但保留3件",
        "异步回调TOCTOU:支付回调与取消订单并发",
        "跨天限额重置:23:59发两笔,Cron重置后第二笔绕过",
        "多版本API最弱者:v1无验签无并发锁但仍可用",
        "客户端UA差异:MiniApp校验宽松,用其UA发Web请求",
        "0元订单退款:0元订单退商品价而非实付",
        "时区混淆:手动改手机时区绕过活动限制",
        "混合支付黑洞:余额+微信->微信0元失败->挂起->退全款->余额多出",
    ],
}

CREATIVE_TIPS = [
    "不是找漏洞,是找功能.做了功能不期望的事就是漏洞.",
    "测试数据/测试账号还在吗?搜test/123456/admin/demo.",
    "API响应多出字段不忽略,下个接口可能用它做权限判断.",
    "越界参数:给负数/空值/字符串/数组,开发者没处理的就是漏洞.",
    "HTTP/1.1换成HTTP/2再试,不同协议行为可能不同.",
    "同样功能WebSocket版可能没鉴权.",
    "条件竞争:同一操作并行10次,触发意想不到的状态.",
    "第三方回调:webhook/callback/SSO回调地址常被信任.",
    "文件上传:SVG/XSL/字体文件也能RCE.",
    "错误信息差异:用户名不存在vs密码错误,可枚举用户名.",
    "找隐藏接口:/api/v2,/internal,/admin,/debug.",
]

BIZ_TIPS = [
    "撤销不等回滚:取消订单后券退回但每人限用计数器是否也回滚",
    "退款精度攻击:退2.9件退290元但保留3件;退0.00001件锁定订单",
    "上一步状态污染:多步流程回退修改金额但上一步状态仍用旧金额",
    "异步回调TOCTOU:支付回调与取消订单并发->退款+发货同时发生",
    "跨天限额重置:23:59发两笔,Cron重置限额后第二笔绕过限制",
    "相同ID不同语义:order_id在退款/用券/发票模块的权限检查不同",
    "复合主键半匹配:只查project权限但task实际在另一个项目",
    "WebSocket心跳注入:心跳包带cart_id,改他人ID变定时泄露通道",
    "导出CSV注入:商品名含换行符->CSV注入假行->导入时执行",
    "触发降级后越权:持续请求触发降级->降级后Auth被跳过",
    "多版本API最弱者:v1/v2/v3同时在线,v1无验签无并发锁",
    "客户端UA差异:MiniApp端校验宽松->用其UA发Web请求绕过",
    "0元订单退款攻击:0元订单退商品价而非实付->退钱到余额",
    "或权限缝隙:role=admin或部门负责人,没限定当前部门->跨部门拿数据",
    "分页反向遍历:page=-1/size=-1/cursor解码改id",
    "手机号格式绕过:+86/0086/空格三个格式注册三个账户",
    "事务不等同:减库存后支付前改收货地址->运费不够",
    "时区混淆:前端JS用本地时间但后端用UTC->绕过活动限制",
    "优惠券负负得正:添加/删除商品时优惠重算有bug->一张券用多次",
    "混合支付精度黑洞:余额+微信->微信0元失败->挂起->退全款->余额多出",
]
# 迂回攻击链: 子公司 -> 收购品牌 -> 海外站 -> 主站
PIVOT_TIPS = [
    "子公司打主站:子公司通常安全投入少->先打子公司->拿到子公司shell或数据->利用子公司对主站的信任关系打主站",
    "收购品牌是薄弱点:刚收购的品牌安全体系还没整合->安全水位最低->从收购品牌撕开口子打到集团",
    "海外站是盲区:海外站通常用不同团队/不同代码库/不同安全策略->比主站弱得多->从海外站撬主站",
    "子域名接管链:找子公司的CNAME指向已删除的云服务->接管子域名->利用通配符cookie打主站",
    "SSO信任链:子公司和主站共用SSO->子公司AD可能没加固->从子公司AD提权到主站资源",
    "OAuth第三方登录:海外站支持Google/GitHub登录->主站可能信任同一OAuth提供商->海外站被入侵=主站可被接管",
    "代码复用漏洞:收购品牌的代码可能被合并到主站->收购品牌的历史漏洞可能在主站仍存在",
    "API信任:主站API信任子公司IP->子公司SSRF打主站内部API->绕过主站WAF",
    "供应链投毒:子公司使用的npm/pip包可能维护较弱->通过子公司供应链投毒打到主站生产环境",
    "CSP/跨域信任链:子公司域名在主站CSP白名单中->子公司XSS即可绕过主站CSP",
]

PIVOT_ORDER = ["子公司", "收购品牌", "海外站", "主站"]


# SRC 终极脑洞 (来自 references/SRC_终极脑洞.md)
ULTRA_TIPS = [
    "时光机考古:翻Wayback Machine 2020-2022的robots.txt,新版删了不等于后端停了",
    "Gau旧版残骸:gau --subs target.com | grep '\.(json|php|aspx|jsp)$' 旧技术栈漏洞温床",
    "HTTP降级差异:CDN接受H2,后端用H1.1 -> 请求走私,重复Host头混淆",
    "RRE逆向溯源:从输出接口(m3u8/json)反向回溯到上游,找谁没鉴权谁没限速",
    "参数注入:A接口的参数整串拼到B接口后端,共享函数等着隐藏参数",
    "超参:limit=-1 pageSize=10000 userId= uid= debug=true admin=true role=admin",
    "小程序云密钥硬编码:反编译wxapkg->搜env/secret/token/key->直接接管云数据库",
    "小程序sessionKey泄露:登录接口返回sessionKey->解密->任意用户伪造登录",
    "SO文件挖密钥:strings libcore.so | grep key/secret/aes/token",
    "Hook绕过四件套:证书锁定/Root检测/生物识别/动态代码加载",
    "异步SSRF蓝海:SVG/PDF上传->URL导入->webhook->OOB payload->几小时后回调到",
    "ClawJacked:恶意网页WS连localhost AI服务->无Origin校验->完全控制AI Agent",
    "AI密钥泄露:搜OPENAI_API_KEY/ANTHROPIC_API_KEY/sk-proj-xxx/sk-ant-xxx",
    "RAG系统SSRF:prompt注入让LLM访问http://169.254.169.254/latest/meta-data/",
    "重定向凭据泄露:302跳转会带走Authorization:Basic头,设恶意服务器收",
    "CI/CD投毒:pull_request_target触发器让PR修改workflow->云凭证泄露",
    "UUID逆向:收集10-20个ID->分析哪些字节变=>和时间相关=>可以预测",
    "协议相对URL绕过://evil.com一行代码绕过白名单",
]

ULTRA_MANTRA = [
    "新版删了不等于后端停用 -- Wayback Machine翻旧版",
    "接口参数可以跨界注入 -- A接口参数喂给B接口",
    "HTTP/1.1 != HTTP/2 -- 差异就是漏洞",
    "小程序云密钥写在JS里 = 白给",
    ".so里的字符串什么都有 -- strings是你好朋友",
    "盲漏洞需要OOB信道 -- 没有Interactsh等于没测",
    "AI本地服务监听localhost != 安全 -- WebSocket跨源直连",
    "302跳转会带走Authorization头",
    "看起来随机的ID往往不随机 -- 时间戳+固定格式",
]



def suggest_upgrade(vuln_class: str) -> list:
    return CHAIN_UPGRADE.get(vuln_class.lower().strip(), [])


def suggest_lateral(vuln_class: str) -> list:
    return LATERAL_EXPANSION.get(vuln_class.lower().strip(), [])


def suggest_creative(count: int = 3) -> list:
    return random.sample(CREATIVE_TIPS, min(count, len(CREATIVE_TIPS)))


def suggest_biz(count: int = 5) -> list:
    return random.sample(BIZ_TIPS, min(count, len(BIZ_TIPS)))


def full_suggestion(vuln_class: str, creative_count: int = 2) -> dict:
    return {
        "vuln_class": vuln_class,
        "upgrade_chains": suggest_upgrade(vuln_class),
        "lateral_expansion": suggest_lateral(vuln_class),
        "creative_tips": suggest_creative(creative_count),
        "biz_tips": suggest_biz(3),
    }


def attach_to_record(technique: str, vuln_class: str) -> str:
    notes = []
    for c in suggest_upgrade(vuln_class):
        notes.append(f"[CHAIN] {c[2]}->{c[3]}: {c[0]}")
        break
    lat = suggest_lateral(vuln_class)
    if lat:
        notes.append(f"[LATERAL] {lat[0]}")
    return " | ".join(notes)


if __name__ == "__main__":
    import sys
    vc = sys.argv[1] if len(sys.argv) > 1 else "xss"
    r = full_suggestion(vc)
    print(f"{vc}: {len(r['upgrade_chains'])} chains, {len(r['lateral_expansion'])} lateral, {len(r['biz_tips'])} biz")
    for t in r['biz_tips']:
        print(f"  biz: {t}")

def suggest_pivot(count: int = 3) -> list:
    return random.sample(PIVOT_TIPS, min(count, len(PIVOT_TIPS)))


def suggest_ultra(count: int = 3) -> list:
    return random.sample(ULTRA_TIPS, min(count, len(ULTRA_TIPS)))

def suggest_mantra(count: int = 3) -> list:
    return random.sample(ULTRA_MANTRA, min(count, len(ULTRA_MANTRA)))
