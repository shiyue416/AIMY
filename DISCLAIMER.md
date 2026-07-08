# 免责声明 / Disclaimer

**工具仅用于授权安全测试，请勿用于非法用途。开发人员不承担任何责任，也不对任何滥用或损坏负责。**

**This tool is for authorized security testing only. Do not use for illegal purposes. The developer assumes no liability and is not responsible for any misuse or damage.**

使用即视为同意以下全部条款。By using it, you agree to all terms below.
> **This tool is for authorized security testing and educational purposes only. By using it, you agree to all terms below.**

---

## 授权范围 / Authorized Use

本工具仅可用于 / This tool may only be used on:

- ✅ 你**拥有**或已获得**书面授权**的资产 / Assets you **own** or have **written authorization** to assess
- ✅ Bug Bounty / SRC 平台明确列入 scope 的目标 / Targets explicitly in-scope for bug bounty programs
- ✅ 已签署 RoE（交战规则）的渗透测试项目 / Pentest engagements with a signed Rules of Engagement
- ✅ CTF 竞赛、自有基础设施、实验靶机 / CTF competitions, your own infrastructure, lab targets

**不确定是否在 scope 内？停止并书面确认后再行动。**
**Unsure whether a target is in-scope? Stop and verify in writing before proceeding.**

---

## 明确排除 / Explicitly Excluded

本工具**不包含**且**不用于** / This tool does **not** include and is **not intended for**:

- ❌ 针对未授权目标的 0-day 武器化 / Weaponizing 0-days against unauthorized targets
- ❌ 后渗透 / 持久化 / 横向移动 / Post-exploitation, persistence, lateral movement
- ❌ 恶意软件或 C2 框架开发 / Malware or C2 framework development
- ❌ 大规模未授权扫描 / Mass unauthorized scanning
- ❌ 凭据填充 / ATO 自动化 / Credential stuffing, ATO automation
- ❌ 供应链投毒 / Supply chain compromise
- ❌ 任何违反以下法律的行为 / Any activity violating: CFAA (美国), UK Computer Misuse Act (英国), 《中华人民共和国网络安全法》(中国), EU Cybercrime Directive (欧盟), or local equivalents

---

## 操作红线 / Operational Red Lines

> 效仿 src-hunter 标准。Modeled after src-hunter operational rules.

| 场景 / Scenario | 红线 / Red Line |
|------|------|
| SQL 注入 / SQLi | 探到库名/版本即停，**不 dump 数据** / Stop at DB name/version, **do not dump data** |
| IDOR / 越权 | 取 **1-3 条**样本即停，不批量拉取 / Pull **1-3 records** max, stop immediately |
| RCE | 只跑 `id` / `whoami` / `uname -a` / Only run `id` / `whoami` / `uname -a` |
| 任意文件读取 / Arbitrary file read | 读到 `root:x:` 即停，**不读 /etc/shadow** / Stop at `root:x:`, **do not read /etc/shadow** |
| 泄露凭据 / Leaked credentials | 仅做一次身份验证调用（`sts get-caller-identity`），**不连接生产环境** / One validation call only, **do not connect to production** |
| 发现数据泄露 / Data leak discovered | **立刻停止**，不扩大获取范围 / **Stop immediately**, do not expand |
| 账号测试 / Account testing | 用自己注册的两个号互测，**不碰他人账号** / Use your own registered accounts, **never touch strangers' accounts** |
| Webshell / heapdump / 源码 | 本地保存，报告后**立刻删除**，**不 push 到 GitHub** / Local only, delete after report, **never push to GitHub** |
| PoC 证据 / Evidence | 所有 PII 脱敏（前2后2位或 SHA256 指纹）/ Redact all PII (first 2 + last 2 chars or SHA256 hash) |

---

## 用户责任 / User Responsibility

使用本工具即表示你确认 / By using this tool, you acknowledge:

- **你对你使用本工具的所有行为负全部责任。** "AI 做的"不构成法律辩护理由。
  **You are fully responsible for all actions taken with this tool.** "The AI did it" is not a legal defense.

- 你有责任确保对目标拥有授权。**不确定 → 停止并书面确认。**
  You are responsible for ensuring you have authorization. **If unsure → stop and verify in writing.**

- 你不会绕过本工具内置的安全门禁（速率限制、只读模式、断路器）。
  You will not bypass the built-in safety gates (rate limiting, read-only mode, circuit breaker).

- 你不会直接提交纯 AI 生成的报告。所有发现必须经过人工验证。
  You will not submit purely AI-generated reports. All findings must be human-verified.

- 部分 SRC 平台（360SRC 等）明文规定：**纯 AI 报告直接驳回，累计 ≥5 条拉黑账号。**
  Some bug bounty platforms explicitly reject AI-only reports and may ban accounts after repeated violations.

---

## 责任限制 / Limitation of Liability

- 本工具按"**现状**"提供，不附带任何明示或默示的保证。
  This tool is provided "**as is**", without warranty of any kind, express or implied.

- 本工具**不保证**发现所有漏洞，也不保证发现均为真实漏洞。
  This tool does **not guarantee** finding all vulnerabilities, nor that findings are true positives.

- 本工具作者**不承担**因使用或误用本工具导致的任何直接或间接损失，包括但不限于：
  安全告警、IP 封禁、法律追责、数据泄露、业务中断。
  The author is **not liable** for any direct or indirect damages arising from the use or misuse of this tool,
  including but not limited to: security alerts, IP bans, legal consequences, data breaches, business interruption.

- 使用本工具可能触发目标系统的安全告警，你应自行评估风险。
  Using this tool may trigger security alerts on target systems. You should assess the risks yourself.

---

## 报告安全问题 / Reporting Security Issues

如果你在本项目中发现了安全漏洞，请通过 GitHub Issues 私下报告，不要公开披露。
If you discover a security issue in this project, please report it privately via GitHub Issues — do not disclose publicly.

---

## 许可证 / License

本项目采用 MIT 许可证。各 Skill 文件见各自许可证。
This project is licensed under MIT. See individual skill files for their respective licenses.

---

> 最后更新 / Last updated: 2026-07-08
