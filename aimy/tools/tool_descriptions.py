"""Human-readable descriptions for discovered security tools.
Maps filename → description so Claude Code knows what each tool does.
"""

TOOL_DESCRIPTIONS = {
    # ── Recon ──
    "active_prober": "主动探测目标端口和服务，识别运行的应用类型和版本",
    "attack_surface": "分析目标的攻击面，识别所有暴露的端口、服务和端点",
    "attack_tree": "构建攻击树模型，可视化从入口点到关键资产的攻击路径",
    "crawler": "爬取目标网站的所有页面和端点，构建完整的站点地图",
    "spa_crawler": "爬取单页应用(SPA)，执行JS渲染以发现隐藏的API端点",
    "recon_engine": "全自动信息收集引擎：子域名枚举+存活验证+URL采集+技术识别",
    "asn_discovery": "通过ASN号反向查询发现同一组织下的所有IP段和域名",
    "favicon_hunt": "通过favicon哈希在FOFA/Shodan上发现使用相同图标的隐藏资产",
    "cdn_origin": "绕过CDN发现网站的真实源服务器IP",
    "csp_intel": "从CSP响应头中提取可信域名列表，发现隐藏的内部资产",
    "js_sourcemap": "从.js.map文件还原TypeScript源码，提取API端点和密钥",
    "permutation_gen": "生成子域名排列变体，发现未被常规枚举覆盖的子域名",
    "cloud_recon": "扫描公有云存储（S3/Azure/GCP），发现公开暴露的存储桶",
    "miniapp_recon": "微信小程序资产侦察，发现小程序相关的API和后台服务",
    "certstream_watch": "实时监控证书透明日志，发现新注册的SSL证书和域名",
    "github_watch": "监控GitHub仓库，发现泄露的代码、密钥和敏感配置",
    "param_discovery": "发现隐藏的HTTP参数，使用Arjun/x8进行智能参数爆破",
    "scope_aggregator": "聚合多个SRC平台的资产范围，统一管理测试目标",

    # ── Vulnerability Scanning ──
    "vuln_scanner": "自动化漏洞扫描：Nuclei模板+CVE检测+配置缺陷+暴露面板",
    "cve_scan": "针对目标的CVE漏洞扫描，聚焦高危和严重级别漏洞",
    "adaptive_fuzzer": "自适应模糊测试引擎，根据目标响应自动调整payload策略",
    "smart_fuzzer": "智能模糊测试：基于机器学习的payload生成和变异",
    "fuzz_engine": "通用模糊测试引擎，支持多种协议和数据格式",
    "payload_engine": "Payload生成引擎，根据目标技术栈自动生成针对性的攻击载荷",
    "payload_mutator": "Payload变异器，对现有payload进行编码/混淆/绕过变换",
    "hai_payload_builder": "AI辅助Payload生成器，利用LLM生成针对特定WAF的绕过载荷",
    "hai_probe": "AI辅助探测工具，智能识别目标技术栈并推荐测试策略",
    "cicd_scanner": "CI/CD管道安全扫描，检测GitHub Actions中的注入和密钥泄露",

    # ── Injection Attacks ──
    "xss_detector": "XSS跨站脚本检测器，支持反射型/存储型/DOM型三种检测模式",
    "xss_validator": "XSS漏洞验证器，自动验证检测到的XSS是否真实可利用",
    "xss_browser_verify": "XSS浏览器验证，在真实浏览器中触发XSS payload确认漏洞",
    "sqli_weaponizer": "SQL注入武器化工具，自动化从检测到数据提取的完整利用链",
    "sqli_blind": "盲SQL注入检测器，支持布尔盲注和时间盲注两种模式",
    "sqli_oob": "OOB外带SQL注入检测器，利用DNS/HTTP外带通道检测注入点",
    "sql_injection": "SQL注入综合检测工具，覆盖Error/Union/Boolean/Time/Stack五种注入",
    "ssti_detector": "SSTI服务器端模板注入检测器，支持Jinja2/Twig/Freemarker等多种引擎",
    "cmdi_detector": "命令注入检测器，检测OS命令注入和代码执行漏洞",
    "lfi_scanner": "本地文件包含(LFI)扫描器，检测路径遍历和文件包含漏洞",
    "nosqli_detector": "NoSQL注入检测器，检测MongoDB/Redis/CouchDB等NoSQL注入",
    "ssrf_detector": "SSRF服务端请求伪造检测器，检测内部网络探测和云元数据访问",
    "ssrf_pwn": "SSRF利用工具，自动化从SSRF检测到内网穿透的完整攻击链",

    # ── Authentication & Authorization ──
    "auth_bypass": "认证绕过检测器，测试多种绕过技术（Header修改/路径变换/方法切换）",
    "auth_engine": "认证引擎，管理多账号会话状态并自动化认证测试流程",
    "dual_session": "双会话对比工具，同时使用两个账号的Session检测IDOR和权限漏洞",
    "jwt_detector": "JWT令牌漏洞检测器，检测算法混淆/密钥泄露/签名绕过等漏洞",
    "jwt_exploiter": "JWT利用工具，自动化JWT令牌的破解、伪造和权限提升攻击",
    "session_matrix": "会话矩阵分析工具，并行测试多个用户角色的权限边界",
    "playwright_auth": "Playwright认证模块，自动化Web登录流程并保持认证状态",

    # ── Business Logic & Race Conditions ──
    "biz_logic_scanner": "业务逻辑漏洞扫描器，检测订单/支付/优惠券等业务流程中的逻辑缺陷",
    "biz_logic_v2": "业务逻辑漏洞扫描器V2，增强版支持更复杂的业务流程建模",
    "race_condition": "条件竞争漏洞检测器，发送并发请求检测竞态条件漏洞",
    "race_profiler": "条件竞争分析器，分析请求时序找出潜在的竞态窗口",
    "h1_race": "HackerOne专项条件竞争测试器，针对SRC平台的漏洞模式优化",

    # ── API & Web Services ──
    "graphql_scanner": "GraphQL API扫描器，检测Introspection/批处理攻击/别名攻击",
    "cors_scanner": "CORS跨域配置检测器，检测Origin反射/Credentials泄露等配置错误",
    "api_fuzz": "API模糊测试，对REST/GraphQL/gRPC接口进行参数和权限测试",
    "http_client": "HTTP客户端，支持自定义请求头/代理/超时的高级HTTP请求发送",
    "mitm_proxy": "中间人代理工具，拦截和分析HTTP/HTTPS流量",
    "flow_reconstructor": "HTTP流量重构工具，从抓包数据中重建完整的请求-响应链",

    # ── IDOR / Authorization ──
    "h1_idor_scanner": "HackerOne专项IDOR扫描器，检测水平越权和垂直越权漏洞",
    "h1_mutation_idor": "IDOR变异测试器，自动变换用户ID格式（UUID→数字→Hash）进行深度测试",
    "h1_oauth_tester": "OAuth 2.0安全测试器，检测redirect_uri/state/scope等参数漏洞",

    # ── WAF & Bypass ──
    "waf_bypass": "WAF绕过综合引擎（35KB），包含编码变换/协议走私/分块传输等多种技术",
    "waf_encoder": "WAF编码器，对payload进行URL/Unicode/Base64/Hex等多重编码绕过WAF",
    "waf_response_analyzer": "WAF响应分析器，比较原始响应和WAF拦截响应的差异",
    "bypass_403": "403/401绕过工具，测试50+种HTTP方法/Header/路径变换绕过技术",
    "multipart_mutator": "Multipart表单变异器，测试文件上传绕过技术",
    "sneaky_bits": "隐蔽传输工具，将数据隐藏在HTTP请求的各个字段中绕过检测",

    # ── Deserialization ──
    "deser_weaponizer": "反序列化武器化工具，自动化生成Java/Python/PHP反序列化利用链",
    "deserialization_detector": "反序列化漏洞检测器，识别应用中的反序列化入口点",

    # ── RCE & Exploitation ──
    "reverse_shell": "反弹Shell生成器，支持多种语言和协议的反弹Shell payload生成",
    "orchestrator": "攻击编排器，协调多个攻击工具按策略顺序执行复杂攻击链",
    "chain_engine": "攻击链引擎，自动发现和组合多个低危漏洞形成高危攻击路径",
    "reasoning_engine": "推理引擎（35KB），使用约束求解算法自动推导最优利用路径",
    "zero_day_fuzzer": "零日漏洞模糊测试器，针对未知漏洞的深度协议级模糊测试",

    # ── Post-Exploitation ──
    "oob_server": "OOB外带服务器，接收DNS/HTTP/LDAP外带回调以确认盲漏洞",
    "packet_capture": "数据包捕获工具，实时抓取和分析网络流量",
    "kali_capture": "Kali Linux集成工具，调用Kali工具链进行渗透测试",
    "kali_executor": "Kali命令执行器，在Kali Linux环境中执行渗透测试命令",
    "kali_toolset": "Kali工具集管理，统一管理和调用Kali Linux的600+安全工具",

    # ── Response Analysis ──
    "response_analyzer": "HTTP响应分析器，深度分析响应头/Body/Cookie的安全特征",
    "response_profiler": "响应画像工具，建立正常响应基线以检测异常行为",
    "semantic_diff": "语义差异分析，比较两个HTTP响应的语义差异发现隐藏漏洞",
    "deviation_oracle": "偏差检测引擎，基于机器学习检测异常HTTP响应模式",

    # ── Knowledge & Planning ──
    "knowledge_graph": "知识图谱引擎，构建资产-漏洞-利用技战术的关联图谱",
    "constraint_graph": "约束图求解器，基于约束传播算法规划最优攻击路径",
    "workflow": "工作流引擎，编排多个安全测试步骤形成自动化测试流水线",
    "workflow_tracer": "工作流追踪器，记录和回放自动化测试的每一步操作",

    # ── Reporting & Validation ──
    "validate": "漏洞验证器，7问法+4关验证确保发现的漏洞真实可利用",
    "verification_oracle": "验证预言机，自动化验证漏洞是否存在及其严重程度",
    "reporter": "报告生成器，自动化生成H1/Bugcrowd/Intigriti格式的漏洞报告",
    "mindmap": "脑图生成器，将测试过程和发现可视化为思维导图",
    "dashboard": "仪表盘生成器，实时显示测试进度和漏洞统计",
    "cvss_version_guard": "CVSS评分计算器，根据漏洞特征自动计算CVSS v3.1评分",
    "dedup_findings": "漏洞去重工具，识别和合并重复的漏洞发现",

    # ── Credential Attacks ──
    "credential_store": "凭证存储管理器，安全管理测试中发现的账号密码和Token",
    "breach_checker": "泄露密码检测器，通过HIBP k-anonymity API检测密码是否已泄露",
    "spray_orchestrator": "密码喷洒编排器，自动化Office365/OAuth/表单等多种认证方式的密码喷洒",
    "osint_employees": "员工信息收集器，通过LinkedIn/GitHub等来源收集目标公司员工信息",
    "wordlist_engine": "字典生成引擎，根据目标公司信息生成定制化的密码字典",

    # ── Token & Crypto ──
    "token_scanner": "代币安全扫描器，检测Meme币/代币合约中的Rug Pull和后门风险",
    "jwt_exploiter": "JWT攻击工具，破解弱密钥/伪造令牌/算法混淆攻击",

    # ── Cloud & Infrastructure ──
    "cloud_recon": "云资源侦察，扫描AWS S3/Azure Blob/GCP Storage中的公开资源",
    "takeover_scanner": "子域名接管扫描器，检测可被接管的DNS记录和云服务",
    "secrets_hunter": "密钥扫描器，使用TruffleHog/Gitleaks检测代码和日志中的泄露密钥",

    # ── Proto Pollution & Advanced ──
    "proto_pollution": "原型链污染检测器，检测JavaScript原型链污染漏洞",
    "html_context_parser": "HTML上下文解析器，分析HTML中的注入上下文以生成精准payload",
    "param_classifier": "参数分类器，自动识别和分类HTTP参数（ID/token/query/action）",
    "param_miner": "参数挖掘器，从JS文件/HTML注释/历史记录中挖掘隐藏参数",

    # ── Playwright Automation ──
    "playwright_engine": "Playwright浏览器引擎，自动化浏览器操作进行动态Web测试",

    # ── CBB Specific ──
    "hunt": "Bug Bounty猎杀编排器，串联目标选择→侦察→扫描→报告完整流程",
    "learn": "漏洞情报学习器，从CVE和公开报告中学习最新的漏洞模式",
    "intel_engine": "威胁情报引擎，收集目标的CVE/Exploit/安全公告等情报",
    "scope_checker": "范围检查器，验证测试目标是否在授权范围内",
    "src_firewall": "SRC防火墙，保护测试过程中的请求速率和安全边界",
    "memory_gc": "内存回收工具，管理猎杀过程中的临时文件和缓存",
    "banner": "Banner生成器，显示AIMY的ASCII艺术Banner",
    "target_selector": "目标选择器，从SRC平台自动筛选高价值测试目标",
    "recon_adapter": "侦察适配器，统一不同侦察工具的输出格式",

    # ── Utility ──
    "external_arsenal": "外部工具注册表，管理50+已安装的安全工具及其版本",
    "mode": "模式管理器，切换veteran(老鸟)/rookie(菜鸟)两种测试模式",
    "settings": "设置管理器，管理AIMY的所有配置项",
    "tool_registry": "工具注册表，管理所有已注册的安全工具的元数据",
    "log_utils": "日志工具，统一的日志记录和格式化",
    "capture": "抓包工具，捕获HTTP请求和响应用于后续分析",
    "scaffold": "脚手架工具，快速创建新的安全工具模板",
    "coverage_record": "测试覆盖记录器，追踪对目标的测试覆盖度",
    "response_tracker": "响应追踪器，记录和分析目标的历史响应变化",
    "journal": "日志管理器，记录完整的测试过程日志",
    "global_brain": "全局Brain模块，管理跨目标的共享知识和模式",
    "cost": "成本追踪器，监控LLM API调用成本",
}

# Batch description overrides
AUTO_DESC = {
    "general": "Security testing tool",
    "recon": "Information gathering and reconnaissance tool",
    "scan": "Vulnerability scanning and detection tool",
    "exploit": "Exploitation and attack automation tool",
    "asset": "Asset discovery and expansion tool",
}
