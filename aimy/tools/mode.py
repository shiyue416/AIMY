from aimy.tools.settings import settings


# ─── 三场景配置文件 ─────────────────────────────────────────
# 每个场景独立定义：红线 / 速率 / 数据安全 / 技能范围 / 输出规范

SCENE_PROFILES = {
    # 🟢 赏金猎人 (Bug Bounty)
    "bounty": {
        "label": "🟢 赏金猎人",
        "desc": "SRC/H1 漏洞挖掘，证明影响→报告→收钱",

        # 红线
        "read_only": True,             # 只读，不做任何写入
        "modify_data": False,          # 严禁修改/删除数据
        "upload_shell": False,         # 严禁上传 webshell
        "bypass_captcha": False,       # 严禁绕过验证码
        "bruteforce_users": False,     # 严禁暴力破解真实用户
        "scan_internal": False,        # 严禁扫描内网
        "mfa_bypass": False,           # 严禁绕过 MFA

        # ⚠️ SRC 合规红线 (各平台通用)
        "ai_report_only": False,       # 严禁纯AI报告 — 提交前必须人工验证+复现
        "ai_report_limit": 3,          # 超3条未经人工验证的AI报告 → 面临封号

        # 速率 (严格)
        "rate_limit": 1.0,             # ≤1 req/s
        "max_concurrency": 3,          # ≤3 并发
        "max_requests_per_day": 500,   # ≤500/天

        # 数据安全
        "max_data_rows": 3,            # 最多3条用户数据
        "max_file_read_lines": 10,     # 最多10行文件
        "pii_masking": "strict",       # PII 强制脱敏

        # 技能加载范围
        "skill_scope": ["web", "api", "auth", "logic"],
        "load_anthropic": False,       # 不加载防御技能
        "post_exploit": False,         # 不进后渗透

        # 输出规范
        "output_style": "concise",     # 简洁，只写有价值的
        "report_format": "h1",         # H1 报告模板
        "filter_low_value": True,      # 过滤低危
        "filter_patterns": ["reflected_xss", "open_redirect", "info_disclosure", "low", "info"],

        # 流程
        "phases": ["intake", "recon", "enum", "hunt", "validate", "report", "flywheel"],
    },

    # 🔵 渗透测试 (Penetration Testing)
    "pentest": {
        "label": "🔵 渗透测试",
        "desc": "授权渗透，找入口→提权→横向→域控",

        # 红线 (有授权)
        "read_only": False,            # 可写入（授权范围内）
        "modify_data": True,           # 可修改（有书面授权）
        "upload_shell": True,          # 可上传 webshell（授权）
        "bypass_captcha": True,        # 可绕过（授权范围）
        "bruteforce_users": True,      # 可暴力破解（授权）
        "scan_internal": True,         # 可扫描内网（授权）
        "mfa_bypass": True,            # 可绕过 MFA（授权）

        # 速率 (适中)
        "rate_limit": 10.0,            # ≤10 req/s
        "max_concurrency": 10,         # ≤10 并发
        "max_requests_per_day": 10000, # ≤10000/天

        # 数据安全
        "max_data_rows": 100,          # 可大量获取（授权）
        "max_file_read_lines": 1000,   # 可读大量文件
        "pii_masking": "report_only",  # 只在最终报告脱敏

        # 技能加载范围
        "skill_scope": ["web", "api", "auth", "logic", "ad", "privsec", "lateral", "cloud"],
        "load_anthropic": True,        # 加载后渗透技能
        "post_exploit": True,          # 进后渗透

        # 输出规范
        "output_style": "detailed",    # 详细输出
        "report_format": "pentest",    # 渗透测试报告模板
        "filter_low_value": False,     # 不过滤低危
        "filter_patterns": [],

        # 流程
        "phases": ["intake", "recon", "enum", "hunt", "validate", "privesc", "lateral", "exfil", "report"],
    },

    # ⚡ 自动渗透 (Auto Pentest) — XBOW 式全自动
    "auto-pentest": {
        "label": "⚡ 自动渗透",
        "desc": "全自动渗透测试，对标 XBOW 速度——28min 跑完一个目标，自动利用链，多模型验证",

        # 红线 (有授权)
        "read_only": False,
        "modify_data": True,
        "upload_shell": True,
        "bypass_captcha": True,
        "bruteforce_users": True,
        "scan_internal": True,
        "mfa_bypass": True,

        # 自动化配置
        "auto_orchestrate": True,       # 自动调度 agent 蜂群
        "auto_chain": True,             # 自动构建利用链 (48步)
        "auto_verify": True,            # 自动确定性验证
        "multi_model_verify": True,     # 多模型交叉验证 (Opus+Sonnet)
        "target_timeout_min": 28,       # 每个目标最多 28 分钟 (对标 XBOW)

        # 速率 (激进)
        "rate_limit": 5.0,             # ≤5 req/s (自动控制)
        "max_concurrency": 8,          # ≤8 并发 (蜂群并行)
        "max_requests_per_day": 5000,

        # Agent 蜂群配置
        "agent_parallel": 5,            # 最多 5 agent 并行
        "agent_exhaust_threshold": 10,  # 连续10次无发现→死胡同
        "hunter_classes": ["idor","xss","ssrf","sqli","rce",
                          "biz","race","graphql","oauth","cors"],

        # 数据安全
        "max_data_rows": 100,
        "max_file_read_lines": 1000,
        "pii_masking": "report_only",

        # 技能加载范围
        "skill_scope": ["web", "api", "auth", "logic", "ad", "privsec", "cloud"],
        "load_anthropic": True,
        "post_exploit": True,

        # 输出规范
        "output_style": "auto_report",   # 自动生成报告
        "report_format": "pentest",
        "filter_low_value": False,
        "filter_patterns": [],

        # 流程 (全自动)
        "phases": ["auto_recon", "auto_hunt_swarm", "auto_verify",
                   "auto_chain", "auto_report", "auto_flywheel"],
    },

    # 🔴 红蓝对抗 (Red Team)
    "redteam": {
        "label": "🔴 红蓝对抗",
        "desc": "隐蔽持久，横向移动，数据窃取，不被发现",

        # 红线 (有授权)
        "read_only": False,
        "modify_data": True,
        "upload_shell": True,
        "bypass_captcha": True,
        "bruteforce_users": True,
        "scan_internal": True,
        "mfa_bypass": True,

        # 速率 (激进但有隐蔽要求)
        "rate_limit": 5.0,             # ≤5 req/s (隐蔽优先)
        "max_concurrency": 5,          # ≤5 并发
        "max_requests_per_day": 5000,  # ≤5000/天

        # 数据安全
        "max_data_rows": 1000,         # 可按需获取
        "max_file_read_lines": 5000,
        "pii_masking": "opsec",        # 操作安全级别脱敏

        # 技能加载范围
        "skill_scope": ["web", "api", "auth", "ad", "privsec", "lateral", "cloud",
                       "c2", "persistence", "evasion", "exfil"],
        "load_anthropic": True,
        "post_exploit": True,

        # 输出规范
        "output_style": "opsec",       # 操作安全优先
        "report_format": "redteam",    # 红队报告模板
        "filter_low_value": False,
        "filter_patterns": [],

        # 流程
        "phases": ["recon", "initial_access", "persistence", "privesc",
                   "lateral", "exfil", "report"],
    },
}


MODE_BANNER = {
    "rookie": """
  ╔══════════════════════════════════════════════╗
  ║         aimy-sikll  菜鸟模式 (Rookie)        ║
  ║  适合入门学习，输出详细说明与修复建议          ║
  ╚══════════════════════════════════════════════╝
""",
    "veteran": """
  ╔══════════════════════════════════════════════╗
  ║         aimy-sikll  老鸟模式 (Veteran)       ║
  ║  专注高价值漏洞，简洁输出，拒绝水洞            ║
  ╚══════════════════════════════════════════════╝
""",
}

SCENE_BANNER = {
    "bounty": """
  ╔══════════════════════════════════════════════╗
  ║         🟢 赏金猎人模式 (Bug Bounty)        ║
  ║  ≤1 req/s | 只读 | 过滤低危 | H1报告        ║
  ║  PII脱敏 | 3条数据上限 | 不进后渗透          ║
  ╚══════════════════════════════════════════════╝
""",
    "pentest": """
  ╔══════════════════════════════════════════════╗
  ║         🔵 渗透测试模式 (Pentest)           ║
  ║  ≤10 req/s | 可写入 | 可提权 | 全技能加载   ║
  ║  详细输出 | 渗透报告 | 授权范围内任意操作    ║
  ╚══════════════════════════════════════════════╝
""",
    "auto-pentest": """
  ╔══════════════════════════════════════════════╗
  ║       ⚡ 自动渗透模式 (Auto Pentest)        ║
  ║  对标 XBOW | 28min/目标 | 蜂群并行          ║
  ║  自动利用链 | 多模型验证 | 全自动报告        ║
  ╚══════════════════════════════════════════════╝
""",
    "redteam": """
  ╔══════════════════════════════════════════════╗
  ║         🔴 红蓝对抗模式 (Red Team)          ║
  ║  ≤5 req/s | 隐蔽优先 | C2/持久化/规避      ║
  ║  操作安全 | 红队报告 | 授权范围内全攻击链   ║
  ╚══════════════════════════════════════════════╝
""",
}


def set_scene(scene: str) -> bool:
    """切换三场景之一。兼容旧版 is_veteran()/is_rookie()。"""
    scene = scene.lower()
    if scene not in SCENE_PROFILES:
        return False

    profile = SCENE_PROFILES[scene]

    # 应用场景配置到 settings
    settings.mode = "veteran" if scene == "bounty" else "rookie"  # ← 兼容旧接口!
    settings.read_only = profile["read_only"]
    settings.rate_limit = profile["rate_limit"]
    settings.max_concurrency = profile["max_concurrency"]
    settings.max_requests_per_day = profile["max_requests_per_day"]
    settings.max_data_rows = profile["max_data_rows"]
    settings.max_file_read_lines = profile["max_file_read_lines"]

    # 存场景元数据
    settings._scene = scene
    settings._scene_profile = profile

    return True


def current_scene() -> str:
    """返回当前场景名。"""
    return getattr(settings, "_scene", "bounty")


def scene_profile() -> dict:
    """返回当前场景配置。"""
    scene = current_scene()
    return SCENE_PROFILES.get(scene, SCENE_PROFILES["bounty"])


def show_scene_banner():
    """显示当前场景横幅。"""
    scene = current_scene()
    banner = SCENE_BANNER.get(scene, SCENE_BANNER["bounty"])
    print(banner)


def show_banner():
    print(MODE_BANNER.get(settings.mode, MODE_BANNER["rookie"]))


def filter_vulnerabilities(results):
    if not isinstance(results, list):
        return results
    profile = scene_profile()
    if profile.get("filter_low_value"):
        patterns = profile.get("filter_patterns", [])
        return [r for r in results if not _is_low_value(r, patterns)]
    return results


def _is_low_value(result, patterns=None):
    if not isinstance(result, dict):
        return False
    if patterns is None:
        patterns = LOW_SIGNAL_PATTERNS
    sig = (result.get("risk") or result.get("severity") or result.get("type") or "").lower()
    for pat in patterns:
        if pat in sig:
            return True
    return False


LOW_SIGNAL_PATTERNS = [
    "reflected_xss", "xss_reflected", "open_redirect",
    "info_disclosure", "low", "info", "information",
]


def enrich_result(result):
    explanations = {
        "sql_injection": {
            "rookie": "SQL注入漏洞: 攻击者可通过注入SQL语句操纵数据库。\n  修复建议: 使用参数化查询(PreparedStatement)或ORM框架。",
            "veteran": "",
        },
        "xss_reflected": {
            "rookie": "反射型XSS: 攻击者构造恶意链接，用户点击后脚本在浏览器执行。\n  修复建议: 对输出进行HTML实体编码，设置Content-Security-Policy。",
            "veteran": "低危: 反射型XSS，不展开。",
        },
        "ssrf": {
            "rookie": "SSRF (服务端请求伪造): 攻击者可诱导服务器发起内部请求。\n  修复建议: 白名单允许的域名/IP，禁止访问内网地址段。",
            "veteran": "",
        },
        "cmdi": {
            "rookie": "命令注入: 攻击者可在服务器执行系统命令。\n  修复建议: 避免将用户输入传入系统命令执行函数，使用白名单校验。",
            "veteran": "",
        },
    }
    if settings.is_rookie() and isinstance(result, dict):
        vuln_type = (result.get("type") or "").lower()
        if vuln_type in explanations:
            result["_explanation"] = explanations[vuln_type]["rookie"]
    return result