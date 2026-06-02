from __future__ import annotations

import json
import httpx

from app.config import get_settings

SYSTEM_PROMPT = """
你是資安 URL 風險分析器。請只輸出 JSON：
{"risk_score":0-100,"risk_level":"LOW|MEDIUM|HIGH","reasons":["..."],"recommended_action":"..."}
判斷依據包含：網址是否模仿品牌、是否要求登入/驗證/付款、語境是否有急迫威脅、網域是否可疑。
""".strip()


async def analyze_with_llm(url: str, context: str) -> dict | None:
    settings = get_settings()
    if not settings.llm_enabled or not settings.openai_api_key:
        return None

    payload = {
        "model": settings.openai_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"URL: {url}\nContext: {context[:2000]}"},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    headers = {"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=settings.scan_timeout_seconds) as client:
        response = await client.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return json.loads(content)
