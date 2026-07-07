# 🛠️ AIMY 自研工具层
> 路径: `C:/Users/PC/Desktop/aimy-skill-main/tools/`
> 规模: 70个 Python 模块，18,889 行代码
> 定位: 外部工具（nuclei/subfinder等）的上层智能调度层

---

## 架构位置

```
你（指令）
    ↓
Claude（融合路由 + 技能调度）
    ↓
AIMY 自研层（本文件，Python智能模块）← 你在这里
    ↓
外部工具层（nuclei/subfinder/httpx/ffuf...）
    ↓
目标
```

---

## 模块分类（10层）

### 🧠 Layer 1 — 核心调度

| 文件 | 行数 | 职责 |
|------|------|------|
| `orchestrator.py` | 1142 | 总调度器，协调所有模块运行 |
| `workflow.py` | 220 | 工作流定义与执行 |
| `workflow_tracer.py` | 294 | 工作流追踪与审计 |
| `tool_registry.py` | 75 | 工具注册与发现 |
| `mode.py` | 70 | 运行模式切换（老鸟/菜鸟） |
| `settings.py` | 190 | 全局配置 |

### 🔍 Layer 2 — 漏洞检测

| 文件 | 行数 | 覆盖漏洞 |
|------|------|---------|
| `ssrf_detector.py` | 409 | SSRF（含云元数据/协议） |
| `auth_bypass.py` | 487 | 认证绕过（JWT/OAuth/逻辑） |
| `ssti_detector.py` | 143 | 服务端模板注入 |
| `cmdi_detector.py` | 214 | 命令注入 |
| `lfi_scanner.py` | 209 | 本地文件包含 |
| `xss_detector.py` | 123 | XSS（反射/存储/DOM） |
| `sql_injection.py` | 275 | SQL注入检测 |
| `cors_scanner.py` | 96 | CORS错误配置 |
| `nosqli_detector.py` | 102 | NoSQL注入 |
| `deserialization_detector.py` | 192 | 反序列化漏洞 |
| `jwt_detector.py` | 156 | JWT安全问题 |
| `graphql_scanner.py` | 107 | GraphQL安全 |
| `proto_pollution.py` | 80 | 原型链污染 |
| `race_condition.py` | 175 | 条件竞争 |

### 💥 Layer 3 — 深度利用

| 文件 | 行数 | 职责 |
|------|------|------|
| `ssrf_pwn.py` | 335 | SSRF → RCE 利用链 |
| `sqli_blind.py` | 575 | 盲注完整利用 |
| `sqli_oob.py` | 135 | SQLi OOB数据提取 |
| `sqli_weaponizer.py` | 64 | SQLi武器化 |
| `jwt_exploiter.py` | 125 | JWT漏洞利用 |
| `deser_weaponizer.py` | 50 | 反序列化武器化 |
| `reverse_shell.py` | 104 | 反弹Shell生成 |
| `waf_bypass.py` | 959 | WAF绕过（最大模块） |

### 🕷️ Layer 4 — 侦察/爬取

| 文件 | 行数 | 职责 |
|------|------|------|
| `crawler.py` | 342 | 基础爬虫 |
| `spa_crawler.py` | 261 | SPA/JS渲染爬取 |
| `attack_surface.py` | 348 | 攻击面识别 |
| `param_miner.py` | 184 | 参数挖掘 |
| `param_classifier.py` | 208 | 参数分类（危险/普通） |
| `active_prober.py` | 296 | 主动探测 |

### 🎯 Layer 5 — 智能Fuzz

| 文件 | 行数 | 职责 |
|------|------|------|
| `adaptive_fuzzer.py` | 408 | 自适应模糊测试 |
| `smart_fuzzer.py` | 276 | 智能Fuzz（基于响应学习） |
| `fuzz_engine.py` | 38 | Fuzz引擎基类 |
| `payload_engine.py` | 522 | Payload生成引擎 |
| `payload_mutator.py` | 53 | Payload变异 |

### 🧮 Layer 6 — 分析推理

| 文件 | 行数 | 职责 |
|------|------|------|
| `reasoning_engine.py` | 926 | AI推理引擎（核心智能） |
| `response_analyzer.py` | 289 | 响应分析 |
| `response_profiler.py` | 142 | 响应特征建模 |
| `semantic_diff.py` | 206 | 语义差异分析 |
| `deviation_oracle.py` | 264 | 偏差检测 |
| `knowledge_graph.py` | 395 | 知识图谱 |
| `attack_tree.py` | 486 | 攻击树建模 |
| `chain_engine.py` | 498 | 漏洞链挖掘 |
| `constraint_graph.py` | 286 | 约束图分析 |

### 🌐 Layer 7 — HTTP/网络

| 文件 | 行数 | 职责 |
|------|------|------|
| `http_client.py` | 375 | HTTP客户端基础 |
| `mitm_proxy.py` | 439 | 中间人代理 |
| `oob_server.py` | 190 | OOB服务器（Blind漏洞验证） |
| `packet_capture.py` | 139 | 数据包捕获 |
| `kali_capture.py` | 261 | Kali流量捕获 |

### 🔐 Layer 8 — 认证/会话

| 文件 | 行数 | 职责 |
|------|------|------|
| `auth_engine.py` | 240 | 认证引擎 |
| `dual_session.py` | 181 | 双会话（越权测试） |
| `session_matrix.py` | 237 | 会话矩阵（多角色测试） |
| `playwright_auth.py` | 315 | 浏览器自动化认证 |
| `playwright_engine.py` | 202 | Playwright引擎 |
| `flow_reconstructor.py` | 193 | 业务流程重建 |

### 📊 Layer 9 — 业务逻辑

| 文件 | 行数 | 职责 |
|------|------|------|
| `biz_logic_scanner.py` | 678 | 业务逻辑漏洞扫描 |
| `biz_logic_v2.py` | 169 | 业务逻辑v2 |
| `race_profiler.py` | 213 | 条件竞争分析 |

### 📝 Layer 10 — 输出/工具集成

| 文件 | 行数 | 职责 |
|------|------|------|
| `reporter.py` | 105 | 报告生成 |
| `kali_executor.py` | 253 | Kali工具执行器 |
| `kali_toolset.py` | 646 | Kali工具集成 |
| `verification_oracle.py` | 156 | 漏洞验证Oracle |
| `log_utils.py` | 23 | 日志工具 |

---

## 与外部工具的分工

```
侦察阶段
  外部: subfinder → httpx → katana → gau
  AIMY: attack_surface.py → param_miner.py → param_classifier.py

检测阶段
  外部: nuclei（已知CVE/配置）
  AIMY: ssrf_detector / auth_bypass / ssti_detector...（逻辑漏洞）

分析阶段
  外部: 无（原始数据输出）
  AIMY: reasoning_engine → deviation_oracle → semantic_diff（智能分析）

利用阶段
  外部: sqlmap（SQLi）/ dalfox（XSS）
  AIMY: ssrf_pwn / sqli_blind / waf_bypass（深度利用+绕WAF）

报告阶段
  外部: 无
  AIMY: reporter.py → H1格式报告
```

---

## 关键模块速查

```bash
# 运行完整流程
cd C:/Users/PC/Desktop/aimy-skill-main
python main.py auto -u https://target.com --mode veteran

# 单模块测试
python -c "from tools.ssrf_detector import SSRFDetector; ..."

# 查看orchestrator支持的动作
python main.py --help
```

---

> 📅 记录时间: 2026-06-30
> 💡 这70个模块是飞轮的**智能大脑**，外部32个工具是**执行双手**
