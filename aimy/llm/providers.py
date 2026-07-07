"""Provider definitions — 11 LLM providers with unified interface.

Provider selection (order of precedence):
  1. AIMY_PROVIDER env var
  2. Auto-detect: first provider whose API key is available

API keys (env vars):
  ANTHROPIC_API_KEY  — Claude
  OPENAI_API_KEY     — OpenAI
  XAI_API_KEY        — Grok
  GROQ_API_KEY       — Groq free tier
  DEEPSEEK_API_KEY   — DeepSeek
  GEMINI_API_KEY     — Google Gemini
  MOONSHOT_API_KEY   — Kimi / Moonshot
  MISTRAL_API_KEY    — Mistral AI
  TOGETHER_API_KEY   — Together AI
  CEREBRAS_API_KEY   — Cerebras
  PERPLEXITY_API_KEY — Perplexity
"""

import os

PROVIDERS: dict[str, dict] = {
    "claude": {
        "label": "Claude (Anthropic)",
        "model": "claude-sonnet-4-6",
        "env_key": "ANTHROPIC_API_KEY",
        "base_url": "https://api.anthropic.com/v1",
        "desc": "Strong security reasoning, excellent tool use",
        "region": "us",
        "group": "国际",
        "cost": "paid",
    },
    "openai": {
        "label": "OpenAI",
        "model": "gpt-4o",
        "env_key": "OPENAI_API_KEY",
        "base_url": "https://api.openai.com/v1",
        "desc": "General-purpose, strong coding",
        "region": "us",
        "group": "国际",
        "cost": "paid",
    },
    "gpt5": {
        "label": "GPT-5.5",
        "model": "gpt-5.5",
        "env_key": "GPT5_API_KEY",
        "base_url": "https://api.openai.com/v1",
        "desc": "最强通用模型，SWE-bench 58.6，xbow 104靶机100%",
        "region": "us",
        "group": "国际",
        "cost": "paid",
    },
    "grok": {
        "label": "Grok (xAI)",
        "model": "grok-2-latest",
        "env_key": "XAI_API_KEY",
        "base_url": "https://api.x.ai/v1",
        "desc": "Fast, strong on code and reasoning",
        "region": "us",
        "group": "国际",
        "cost": "paid",
    },
    "groq": {
        "label": "Groq (Free Tier)",
        "model": "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
        "base_url": "https://api.groq.com/openai/v1",
        "desc": "Cloud free tier — Llama 3.3 70B",
        "region": "us",
        "group": "国际",
        "cost": "free",
    },
    "deepseek": {
        "label": "DeepSeek",
        "model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com/v1",
        "desc": "Cheap, strong reasoning, long context",
        "region": "cn",
        "group": "中国",
        "cost": "cheap",
    },
    "gemini": {
        "label": "Google Gemini",
        "model": "gemini-2.0-flash",
        "env_key": "GEMINI_API_KEY",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "desc": "Fast, good for triage and quick analysis",
        "region": "us",
        "group": "国际",
        "cost": "cheap",
    },
    "kimi": {
        "label": "Kimi / Moonshot",
        "model": "moonshot-v1-128k",
        "env_key": "MOONSHOT_API_KEY",
        "base_url": "https://api.moonshot.cn/v1",
        "desc": "Long context (128K), strong Chinese",
        "region": "cn",
        "group": "中国",
        "cost": "cheap",
    },
    "mistral": {
        "label": "Mistral AI",
        "model": "mistral-large-latest",
        "env_key": "MISTRAL_API_KEY",
        "base_url": "https://api.mistral.ai/v1",
        "desc": "Strong coding, EU-hosted",
        "region": "eu",
        "group": "国际",
        "cost": "paid",
    },
    "together": {
        "label": "Together AI",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "env_key": "TOGETHER_API_KEY",
        "base_url": "https://api.together.xyz/v1",
        "desc": "Cloud Llama/Qwen access",
        "region": "us",
        "group": "国际",
        "cost": "cheap",
    },
    "cerebras": {
        "label": "Cerebras",
        "model": "llama3.3-70b",
        "env_key": "CEREBRAS_API_KEY",
        "base_url": "https://api.cerebras.ai/v1",
        "desc": "Ultra-fast inference",
        "region": "us",
        "group": "国际",
        "cost": "cheap",
    },
    "perplexity": {
        "label": "Perplexity AI",
        "model": "sonar-pro",
        "env_key": "PERPLEXITY_API_KEY",
        "base_url": "https://api.perplexity.ai",
        "desc": "Live web search built-in",
        "region": "us",
        "group": "国际",
        "cost": "paid",
    },
    "longcat": {
        "label": "美团龙猫 LongCat-2.0",
        "model": "meituan/longcat-2.0",
        "env_key": "LONGCAT_API_KEY",
        "base_url": "https://api.aimlapi.com/v1",
        "desc": "1.6T MoE, 1M ctx, 国产算力, SWE-bench 59.5",
        "region": "cn",
        "group": "中国",
        "cost": "cheap",
    },
    # OpenRouter (通过它可访问 200+ 模型)
    "openrouter": {
        "label": "OpenRouter (多模型网关)",
        "model": "meituan/longcat-2.0",
        "env_key": "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1",
        "desc": "200+ models including LongCat, DeepSeek, Llama...",
        "region": "us",
        "group": "网关",
        "cost": "varies",
    },
}

# Priority: free-cloud first, cheap second, paid last
PROVIDER_PRIORITY = [
    "groq", "deepseek", "cerebras",
    "gemini", "kimi", "mistral", "together",
    "perplexity", "longcat", "claude", "openai", "gpt5", "grok",
    "openrouter",
]

# Phase-based model routing
PHASE_MODELS = {
    "recon":     ["groq", "deepseek"],           # cheap is fine
    "scan":      ["groq", "deepseek"],           # high volume, cheap
    "triage":    ["groq", "claude", "longcat", "gpt5"],  # needs reasoning
    "chains":    ["claude", "longcat", "gpt5", "deepseek", "openai"], # deep reasoning needed
    "report":    ["claude", "longcat", "gpt5", "openai", "deepseek"],  # quality matters
    "js":        ["claude", "deepseek", "longcat", "groq", "gpt5"],  # code analysis
    "autopilot": ["groq", "deepseek", "longcat"],           # long-running, cheap
    "plan":      ["claude", "gpt5", "openai", "longcat", "deepseek"],  # strategic thinking
    "exploit":   ["claude", "longcat", "gpt5", "deepseek", "openai"],  # complex chains
}

# Model capability matrix (1-10)
MODEL_PROFILES = {
    "claude":  {"general": 9, "coding": 9, "reasoning": 10, "chinese": 6, "speed": 7},
    "openai":  {"general": 9, "coding": 9, "reasoning": 8, "chinese": 7, "speed": 8},
    "grok":    {"general": 8, "coding": 8, "reasoning": 8, "chinese": 5, "speed": 9},
    "groq":    {"general": 7, "coding": 7, "reasoning": 6, "chinese": 5, "speed": 10},
    "deepseek":{"general": 8, "coding": 9, "reasoning": 9, "chinese": 9, "speed": 6},
    "gemini":  {"general": 8, "coding": 8, "reasoning": 7, "chinese": 6, "speed": 10},
    "kimi":    {"general": 7, "coding": 7, "reasoning": 7, "chinese": 10, "speed": 7},
    "mistral": {"general": 8, "coding": 9, "reasoning": 8, "chinese": 5, "speed": 7},
    "together":{"general": 7, "coding": 7, "reasoning": 6, "chinese": 6, "speed": 8},
    "cerebras":{"general": 7, "coding": 7, "reasoning": 6, "chinese": 5, "speed": 10},
    "perplexity":{"general": 8, "coding": 6, "reasoning": 8, "chinese": 6, "speed": 5},
    "longcat":   {"general": 9, "coding": 9, "reasoning": 9, "chinese": 9, "speed": 7},
    "openrouter":{"general": 9, "coding": 9, "reasoning": 9, "chinese": 8, "speed": 6},
    "gpt5":      {"general": 10, "coding": 10, "reasoning": 10, "chinese": 8, "speed": 9},
}


def get_available_providers() -> list[str]:
    """Return sorted list of providers whose API keys are set."""
    key_env = {
        "claude": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "grok": "XAI_API_KEY",
        "groq": "GROQ_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "kimi": "MOONSHOT_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "together": "TOGETHER_API_KEY",
        "cerebras": "CEREBRAS_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
        "longcat": "LONGCAT_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "gpt5": "GPT5_API_KEY",
    }
    available = []
    for p, env in key_env.items():
        if os.environ.get(env):
            available.append(p)
    return sorted(set(available))


def get_provider_config(provider: str) -> dict | None:
    """Get full config for a provider."""
    return PROVIDERS.get(provider.lower())
