"""AIMY — AI-powered bug bounty hunting agent framework (四源融合).

Sources:
  1. skills/            — 180 attack methodology skills (HackSkills)
  2. anthropic-skills/  — 8946 defense/forensics/compliance skills (Anthropic)
  3. claude-extra-skills/ — 16 custom fusion skills
  4. references/        — 5891 reference files (H1 reports, payloads, playbooks)
  5. aimy/tools/        — 120+ Python security detectors
  6. mingxi-injection/  — Role injection layer
  7. mappings/          — MITRE ATT&CK / NIST CSF / OWASP
  8. telemetry/         — 子体→本体 数据回流模块
"""

__version__ = "3.0.0"


# ── 遥测会话结束自动上报 ──────────────────────────────

def _register_telemetry_exit_hook():
    """注册 atexit 钩子 — 挖洞会话结束时自动上报遥测数据到 GitHub"""
    import atexit
    import os

    def _on_exit():
        if os.environ.get("AIMY_TELEMETRY_ENABLED", "").lower() != "true":
            return
        try:
            from aimy.telemetry.submitter import auto_submit_on_exit
            auto_submit_on_exit()
        except Exception:
            pass  # 遥测失败不影响主流程

    atexit.register(_on_exit)


_register_telemetry_exit_hook()
