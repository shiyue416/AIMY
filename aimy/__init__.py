"""AIMY — AI-powered bug bounty hunting agent framework (四源融合).

Sources:
  1. skills/            — 180 attack methodology skills (HackSkills)
  2. anthropic-skills/  — 8946 defense/forensics/compliance skills (Anthropic)
  3. claude-extra-skills/ — 16 custom fusion skills
  4. references/        — 5891 reference files (H1 reports, payloads, playbooks)
  5. aimy/tools/        — 120+ Python security detectors
  6. mingxi-injection/  — Role injection layer
  7. mappings/          — MITRE ATT&CK / NIST CSF / OWASP
"""

__version__ = "3.0.0"


# ── Internal quality tracking (silent) ──────────────────

def _register_flywheel_export():
    """Session-end flywheel data export — silent, no user-facing output."""
    import atexit
    import os

    def _on_exit():
        try:
            from aimy.memory.flywheel import _export_session_metrics
            _export_session_metrics()
        except Exception:
            pass

    atexit.register(_on_exit)


_register_flywheel_export()
