"""LLMClient — unified chat interface for 11 LLM providers.

Usage:
    client = LLMClient()            # auto-detect
    client = LLMClient("claude")    # force Claude
    reply  = client.chat(model, system_prompt, user_prompt)

    # With tool calling (OpenAI-compatible providers):
    reply, tool_calls = client.chat_with_tools(model, system, user, tools)

Free/cheap providers:
    groq     — cloud free tier
    deepseek — very cheap
"""

from __future__ import annotations

import json
import os
from typing import Any


class LLMClient:
    """Unified chat interface for Groq, DeepSeek, Claude, OpenAI, Grok,
    Gemini, Kimi, Mistral, Together, Cerebras, and Perplexity."""

    PROVIDER_PRIORITY = [
        "groq", "deepseek", "cerebras",
        "gemini", "kimi", "mistral", "together",
        "perplexity", "longcat", "claude", "openai", "grok",
        "openrouter",
    ]

    DEFAULT_MODELS = {
        "claude":     "claude-sonnet-4-6",
        "openai":     "gpt-4o",
        "grok":       "grok-2-latest",
        "groq":       "llama-3.3-70b-versatile",
        "deepseek":   "deepseek-chat",
        "gemini":     "gemini-2.0-flash",
        "kimi":       "moonshot-v1-128k",
        "mistral":    "mistral-large-latest",
        "together":   "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "cerebras":   "llama3.3-70b",
        "perplexity": "sonar-pro",
        "longcat":    "meituan/longcat-2.0",
        "openrouter": "meituan/longcat-2.0",
        "gpt5":       "gpt-5.5",
    }

    PROVIDER_KEY_ENV = {
        "claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
        "grok": "XAI_API_KEY", "groq": "GROQ_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY", "gemini": "GEMINI_API_KEY",
        "longcat": "LONGCAT_API_KEY", "openrouter": "OPENROUTER_API_KEY",
        "kimi": "MOONSHOT_API_KEY", "mistral": "MISTRAL_API_KEY",
        "together": "TOGETHER_API_KEY", "cerebras": "CEREBRAS_API_KEY",
        "perplexity": "PERPLEXITY_API_KEY",
    }

    def __init__(self, provider: str | None = None):
        self.provider = (provider or os.environ.get("BRAIN_PROVIDER", "")).lower()
        self._http = None
        self._api_base = ""
        self._anthropic_client = None
        self._anthropic_key = ""
        self.available = False
        self.description = ""

        if not self.provider:
            self.provider = self._auto_detect()
        else:
            self._init_provider(self.provider)

    # ── Auto-detection ────────────────────────────────────────────

    def _auto_detect(self) -> str:
        """Find first available provider. Key-based providers only."""
        key_providers = [p for p, env in self.PROVIDER_KEY_ENV.items()
                         if os.environ.get(env)]
        rest = [p for p in self.PROVIDER_PRIORITY if p not in key_providers]
        for p in key_providers + rest:
            try:
                self._init_provider(p)
                if self.available:
                    return p
            except Exception:
                pass
        return "groq"  # fallback (likely unavailable, user will see error)

    def _init_provider(self, provider: str) -> None:
        """Initialize a specific provider connection."""
        self.available = False

        if provider == "claude":
            key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not key: return
            try:
                import anthropic as _anthropic
                self._anthropic_client = _anthropic.Anthropic(api_key=key)
                self.available = True
                self.description = "Claude API (Anthropic SDK)"
            except ImportError:
                import requests
                self._http = requests.Session()
                self._http.headers.update({
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                })
                self._anthropic_key = key
                self.available = True
                self.description = "Claude API (HTTP fallback)"

        elif provider in ("openai", "grok", "groq", "deepseek", "gemini",
                          "kimi", "mistral", "together", "cerebras", "perplexity"):
            env_key = self.PROVIDER_KEY_ENV.get(provider, "")
            key = os.environ.get(env_key, "")
            if not key: return
            import requests
            self._http = requests.Session()
            self._http.headers.update({
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            })
            base_urls = {
                "openai": "https://api.openai.com/v1",
                "grok": "https://api.x.ai/v1",
                "groq": "https://api.groq.com/openai/v1",
                "deepseek": "https://api.deepseek.com/v1",
                "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
                "kimi": "https://api.moonshot.cn/v1",
                "mistral": "https://api.mistral.ai/v1",
                "together": "https://api.together.xyz/v1",
                "cerebras": "https://api.cerebras.ai/v1",
                "perplexity": "https://api.perplexity.ai",
            }
            self._api_base = base_urls.get(provider, "")
            self.available = True
            self.description = f"{provider.title()} API"

    # ── Chat (text only) ──────────────────────────────────────────

    def chat(self, model: str | None, system: str, user: str,
             max_tokens: int = 4000, temperature: float = 0.1) -> str:
        """Send a chat request; return the assistant reply as a string."""
        if not self.available:
            return ""
        try:
            if self.provider == "claude":
                return self._chat_claude(model, system, user, max_tokens, temperature)
            else:
                return self._chat_openai_compat(model, system, user, max_tokens, temperature)
        except Exception:
            return ""

    def _chat_claude(self, model, system, user, max_tokens, temperature) -> str:
        m = model or self.DEFAULT_MODELS["claude"]
        if self._anthropic_client:
            resp = self._anthropic_client.messages.create(
                model=m, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user}],
            )
            return resp.content[0].text.strip()
        # HTTP fallback
        body = {"model": m, "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": user}]}
        r = self._http.post("https://api.anthropic.com/v1/messages",
                            data=json.dumps(body), timeout=120)
        r.raise_for_status()
        return r.json()["content"][0]["text"].strip()

    def _chat_openai_compat(self, model, system, user, max_tokens, temperature) -> str:
        m = model or self.DEFAULT_MODELS[self.provider]
        body = {"model": m, "max_tokens": max_tokens, "temperature": temperature,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        r = self._http.post(f"{self._api_base}/chat/completions",
                            data=json.dumps(body), timeout=120)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()

    # ── Chat (with tool calling) ─────────────────────────────────

    def chat_with_tools(self, model: str | None, system: str, user: str,
                        tools: list[dict[str, Any]],
                        max_tokens: int = 4000, temperature: float = 0.1
                        ) -> tuple[str, list[dict[str, Any]]]:
        """Send a chat request with tool definitions.

        Returns: (text_reply, tool_calls_list)
          tool_calls = [{"name": "...", "arguments": {...}}, ...]
        """
        if not self.available:
            return "", []
        try:
            if self.provider == "claude":
                return self._chat_tools_claude(model, system, user, tools, max_tokens, temperature)
            else:
                return self._chat_tools_openai(model, system, user, tools, max_tokens, temperature)
        except Exception:
            return "", []

    def _chat_tools_claude(self, model, system, user, tools, max_tokens, temperature):
        # Convert OpenAI tool format to Anthropic tool format
        anthropic_tools = []
        for t in tools:
            if t.get("type") == "function" and "function" in t:
                f = t["function"]
                anthropic_tools.append({
                    "name": f["name"],
                    "description": f.get("description", ""),
                    "input_schema": f.get("parameters", {"type": "object", "properties": {}, "required": []}),
                })

        m = model or self.DEFAULT_MODELS["claude"]
        if self._anthropic_client:
            resp = self._anthropic_client.messages.create(
                model=m, max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                tools=anthropic_tools,
            )
        else:
            body = {"model": m, "max_tokens": max_tokens, "system": system,
                    "messages": [{"role": "user", "content": user}],
                    "tools": anthropic_tools}
            r = self._http.post("https://api.anthropic.com/v1/messages",
                                data=json.dumps(body), timeout=120)
            r.raise_for_status()
            resp = r.json()

        text = ""
        tool_calls = []
        for block in resp.get("content", []) if isinstance(resp, dict) else resp.content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    text += block.get("text", "")
                elif block.get("type") == "tool_use":
                    tool_calls.append({"name": block["name"], "arguments": block["input"]})
            elif hasattr(block, "type"):
                if block.type == "text":
                    text += block.text
                elif block.type == "tool_use":
                    tool_calls.append({"name": block.name, "arguments": block.input})
        return text.strip(), tool_calls

    def _chat_tools_openai(self, model, system, user, tools, max_tokens, temperature):
        m = model or self.DEFAULT_MODELS[self.provider]
        body = {"model": m, "max_tokens": max_tokens, "temperature": temperature,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}],
                "tools": tools, "tool_choice": "auto"}
        r = self._http.post(f"{self._api_base}/chat/completions",
                            data=json.dumps(body), timeout=120)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        text = msg.get("content", "") or ""
        tool_calls = []
        for tc in msg.get("tool_calls", []) or []:
            args_str = tc.get("function", {}).get("arguments", "{}")
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                args = {}
            tool_calls.append({"name": tc.get("function", {}).get("name", ""), "arguments": args})
        return text.strip(), tool_calls

    # ── Helpers ───────────────────────────────────────────────────

    def list_models(self) -> list[str]:
        """List default model for the current provider."""
        return list(self.DEFAULT_MODELS.get(self.provider, []))

    @classmethod
    def detect_best(cls) -> "LLMClient":
        """Create a client with the best available provider."""
        return cls()  # auto-detection in __init__
