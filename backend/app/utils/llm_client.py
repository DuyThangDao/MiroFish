"""
LLM客户端封装
统一使用OpenAI格式调用，支持 AI Studio API key 和 Vertex AI Service Account
"""

import json
import re
from typing import Optional, Dict, Any, List
from openai import OpenAI

from ..config import Config


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


class LLMClient:
    """LLM客户端"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None
    ):
        self.base_url = base_url or Config.LLM_BASE_URL
        self.model = model or Config.LLM_MODEL_NAME

        vertex_key_file = Config.LLM_VERTEX_AI_KEY_FILE
        if vertex_key_file:
            # Vertex AI mode: dùng service account JSON, bỏ qua LLM_API_KEY
            http_client = _build_vertex_ai_http_client(vertex_key_file)
            self.client = OpenAI(
                api_key="vertex-ai",  # placeholder, bị override bởi httpx auth
                base_url=self.base_url,
                http_client=http_client,
                max_retries=0,
            )
        else:
            # Standard mode: AI Studio / OpenAI / Groq / Ollama
            self.api_key = api_key or Config.LLM_API_KEY
            if not self.api_key:
                raise ValueError("LLM_API_KEY 未配置")
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=1800,   # 30 min — sufficient for large model responses
                max_retries=0,  # disable built-in retry; caller handles rate limiting
            )
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 4096,
        response_format: Optional[Dict] = None
    ) -> str:
        """
        发送聊天请求
        
        Args:
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            response_format: 响应格式（如JSON模式）
            
        Returns:
            模型响应文本
        """
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        
        if response_format:
            kwargs["response_format"] = response_format
        
        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0] if response.choices else None
        content = (choice.message.content if choice and choice.message else None) or ""
        # 部分模型（如MiniMax M2.5）会在content中包含<think>思考内容，需要移除
        content = re.sub(r'<think>[\s\S]*?</think>', '', content).strip()
        return content
    
    def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 4096
    ) -> Dict[str, Any]:
        """
        发送聊天请求并返回JSON
        
        Args:
            messages: 消息列表
            temperature: 温度参数
            max_tokens: 最大token数
            
        Returns:
            解析后的JSON对象
        """
        response = self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"}
        )
        # 清理markdown代码块标记
        cleaned_response = response.strip()
        cleaned_response = re.sub(r'^```(?:json)?\s*\n?', '', cleaned_response, flags=re.IGNORECASE)
        cleaned_response = re.sub(r'\n?```\s*$', '', cleaned_response)
        cleaned_response = cleaned_response.strip()

        try:
            return json.loads(cleaned_response)
        except json.JSONDecodeError:
            raise ValueError(f"LLM返回的JSON格式无效: {cleaned_response}")

