"""
LLM客户端封装
统一使用OpenAI格式调用，支持 AI Studio API key 和 Vertex AI Service Account
Ngoài ra hỗ trợ AnthropicVertex mode: Claude models trên Vertex AI (dùng anthropic SDK)
"""

import json
import re
import time
import logging
from typing import Optional, Dict, Any, List
from openai import OpenAI

from ..config import Config

_logger = logging.getLogger("mirofish.llm_client")

# ─── Global rate limiter (shared across all threads/processes) ────────────────
import fcntl
import os as _os
import threading

_GLOBAL_RPM_FILE = "/tmp/mirofish_rpm_0.json"
_GLOBAL_RPM_LOCK = "/tmp/mirofish_rpm_0.lock"


def _acquire_global_slot(slot_file: str = _GLOBAL_RPM_FILE,
                         lock_file: str = _GLOBAL_RPM_LOCK,
                         limit: int = 0):
    """Block until a slot is available in the per-account RPM window."""
    if limit <= 0:
        limit = int(_os.environ.get("LLM_GLOBAL_RPM_LIMIT", "0"))
    if limit <= 0:
        return  # limiter disabled

    while True:
        wait_for = 0.0
        with open(lock_file, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                now = time.time()
                cutoff = now - 60.0
                try:
                    import json as _json
                    with open(slot_file) as f:
                        data = _json.load(f)
                    ts = [t for t in data.get("ts", []) if t > cutoff]
                except (FileNotFoundError, ValueError):
                    ts = []

                if len(ts) < limit:
                    ts.append(now)
                    import json as _json
                    with open(slot_file, "w") as f:
                        _json.dump({"ts": ts}, f)
                    return  # slot acquired

                wait_for = ts[0] + 60.0 - now + 0.1
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

        time.sleep(min(wait_for, 1.0))


def _build_vertex_ai_http_client(key_file: str):
    """Tạo httpx.Client với Vertex AI auth tự động refresh token."""
    import httpx
    from google.oauth2 import service_account
    import google.auth.transport.requests

    credentials = service_account.Credentials.from_service_account_file(
        key_file,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    class _VertexAuth(httpx.Auth):
        def auth_flow(self, request):
            if not credentials.valid:
                credentials.refresh(google.auth.transport.requests.Request())
            request.headers["Authorization"] = f"Bearer {credentials.token}"
            yield request

    return httpx.Client(auth=_VertexAuth(), timeout=1800)


def _extract_project_id(key_file: str) -> str:
    """Đọc project_id từ service account JSON."""
    with open(key_file) as f:
        return json.load(f).get("project_id", "")


class LLMClient:
    """LLM客户端

    Hỗ trợ 4 mode:
      1. Vertex AI Gemini  — vertex_key_file set, không có anthropic_vertex_region
      2. AnthropicVertex   — vertex_key_file + anthropic_vertex_region → Claude trên Vertex AI
      3. Anthropic API key — base_url chứa anthropic.com → OpenAI-compat + header
      4. Standard OpenAI   — api_key only
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        vertex_key_file: Optional[str] = None,
        anthropic_vertex_region: Optional[str] = None,
        rpm_slot_file: Optional[str] = None,
        rpm_limit: Optional[int] = None,
    ):
        self.base_url = base_url or Config.LLM_BASE_URL
        self.model = model or Config.LLM_MODEL_NAME
        self._is_anthropic = False
        self._is_anthropic_vertex = False
        self._av_client = None  # AnthropicVertex client instance
        self._rpm_slot_file = rpm_slot_file or _GLOBAL_RPM_FILE
        self._rpm_lock_file = self._rpm_slot_file.replace(".json", ".lock")
        self._rpm_limit = rpm_limit  # None → reads LLM_GLOBAL_RPM_LIMIT from env

        resolved_vertex = vertex_key_file or (
            Config.LLM_VERTEX_AI_KEY_FILE if not api_key else None
        )

        if resolved_vertex and anthropic_vertex_region:
            # ── Mode 2: AnthropicVertex — Claude trên Vertex AI ──────────────
            self._is_anthropic_vertex = True
            self._is_anthropic = True
            from anthropic import AnthropicVertex
            from google.oauth2 import service_account as _sa
            credentials = _sa.Credentials.from_service_account_file(
                resolved_vertex,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            project_id = _extract_project_id(resolved_vertex)
            self._av_client = AnthropicVertex(
                project_id=project_id,
                region=anthropic_vertex_region,
                credentials=credentials,
            )
            self.client = None  # không dùng OpenAI client trong mode này
            _logger.info(
                f"LLMClient: AnthropicVertex mode | model={self.model} "
                f"| region={anthropic_vertex_region} | project={project_id}"
            )

        elif resolved_vertex:
            # ── Mode 1: Vertex AI Gemini ──────────────────────────────────────
            http_client = _build_vertex_ai_http_client(resolved_vertex)
            self.client = OpenAI(
                api_key="vertex-ai",  # placeholder, bị override bởi httpx auth
                base_url=self.base_url,
                http_client=http_client,
                max_retries=0,
            )

        elif base_url and "anthropic.com" in (base_url or ""):
            # ── Mode 3: Anthropic API key (OpenAI-compat) ─────────────────────
            self._is_anthropic = True
            resolved_key = api_key or getattr(Config, "BOOST_API_KEY", None)
            if not resolved_key:
                raise ValueError("BOOST_API_KEY not set for Anthropic endpoint")
            self.client = OpenAI(
                api_key=resolved_key,
                base_url=self.base_url,
                default_headers={"anthropic-version": "2023-06-01"},
                timeout=1800,
                max_retries=0,
            )

        else:
            # ── Mode 4: Standard OpenAI / AI Studio / Groq / Ollama ──────────
            self.api_key = api_key or Config.LLM_API_KEY
            if not self.api_key:
                raise ValueError("LLM_API_KEY 未配置")
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=1800,
                max_retries=0,
            )

    # ─── AnthropicVertex chat ─────────────────────────────────────────────────

    def _chat_anthropic_vertex(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Gọi Claude trên Vertex AI qua anthropic SDK."""
        # Tách system message ra (Anthropic API yêu cầu riêng)
        system_content = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            else:
                user_messages.append({"role": msg["role"], "content": msg["content"]})

        if not user_messages:
            user_messages = [{"role": "user", "content": "(no content)"}]

        max_retries = 5
        base_delay  = 15
        for attempt in range(max_retries):
            try:
                _acquire_global_slot(self._rpm_slot_file, self._rpm_lock_file, self._rpm_limit or 0)
                kwargs: Dict[str, Any] = {
                    "model":       self.model,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                    "messages":    user_messages,
                }
                if system_content:
                    kwargs["system"] = system_content

                response = self._av_client.messages.create(**kwargs)
                break
            except Exception as e:
                is_rate_limit = ("429" in str(e) or
                                 "rate" in str(e).lower() or
                                 "quota" in str(e).lower() or
                                 "overloaded" in str(e).lower())
                if is_rate_limit and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    _logger.warning(
                        f"[AnthropicVertex] Rate limit (attempt {attempt+1}/{max_retries}), "
                        f"waiting {delay}s..."
                    )
                    time.sleep(delay)
                else:
                    raise

        # Anthropic response: response.content[0].text
        if response.content and hasattr(response.content[0], "text"):
            return response.content[0].text or ""
        return ""

    # ─── Public interface ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        response_format: Optional[Dict] = None,
        strip_think: bool = True,
    ) -> str:
        """发送聊天请求"""
        if self._is_anthropic_vertex:
            return self._chat_anthropic_vertex(messages, temperature, max_tokens)

        kwargs = {
            "model":       self.model,
            "messages":    messages,
            "temperature": temperature,
            "max_tokens":  max_tokens,
        }
        if response_format:
            kwargs["response_format"] = response_format

        max_retries = 5
        base_delay  = 15
        for attempt in range(max_retries):
            try:
                _acquire_global_slot(self._rpm_slot_file, self._rpm_lock_file, self._rpm_limit or 0)
                response = self.client.chat.completions.create(**kwargs)
                break
            except Exception as e:
                is_rate_limit = ("429" in str(e) or
                                 "rate" in str(e).lower() or
                                 "quota" in str(e).lower() or
                                 "resource_exhausted" in str(e).lower())
                if is_rate_limit and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    _logger.warning(
                        f"Rate limit hit (attempt {attempt+1}/{max_retries}). "
                        f"Waiting {delay}s before retry..."
                    )
                    time.sleep(delay)
                else:
                    raise

        choice = response.choices[0] if response.choices else None
        content = (choice.message.content if choice and choice.message else None) or ""
        if strip_think:
            content = re.sub(r'<think>[\s\S]*?</think>', '', content).strip()
        return content

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096
    ) -> Dict[str, Any]:
        """发送聊天请求并返回JSON"""
        # Anthropic (both Vertex and API-key mode) enforces JSON via prompt, not response_format
        fmt = None if self._is_anthropic else {"type": "json_object"}
        response = self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=fmt,
        )
        cleaned = response.strip()
        cleaned = re.sub(r'^```(?:json)?\s*\n?', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'\n?```\s*$', '', cleaned)
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            raise ValueError(f"LLM返回的JSON格式无效: {cleaned}")


class LLMClientPool:
    """Round-robin pool across multiple LLMClient instances.

    Drop-in replacement for LLMClient — exposes the same chat() / chat_json()
    interface. Each call is dispatched to the next client in rotation, spreading
    load evenly across Vertex AI accounts. Thread-safe.
    """

    def __init__(self, clients: List[LLMClient]):
        if not clients:
            raise ValueError("LLMClientPool requires at least one client")
        self._clients = clients
        self._idx = 0
        self._lock = threading.Lock()

    def _next(self) -> LLMClient:
        with self._lock:
            c = self._clients[self._idx % len(self._clients)]
            self._idx += 1
            return c

    @property
    def pool_size(self) -> int:
        return len(self._clients)

    @property
    def model(self) -> str:
        return self._clients[0].model

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        response_format: Optional[Dict] = None,
        strip_think: bool = True,
    ) -> str:
        return self._next().chat(
            messages, temperature=temperature, max_tokens=max_tokens,
            response_format=response_format, strip_think=strip_think,
        )

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        return self._next().chat_json(messages, temperature=temperature, max_tokens=max_tokens)
