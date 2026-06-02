import json
from openai import AsyncOpenAI
from app.config import get_settings
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.rule_checker import check_rules

SYSTEM_PROMPT = """
你是資安釣魚網站風險分析器。請根據 URL、頁面標題、上下文文字、頁面連結與本地規則結果，判斷是否可能是釣魚或詐騙。
只輸出 JSON，不要使用 Markdown。格式如下：
{
  "riskLevel": "LOW" | "MEDIUM" | "HIGH",
  "score": 0-100,
  "reasons": ["原因1", "原因2"],
  "aiSummary": "給一般使用者看的繁體中文簡短說明"
}
判斷原則：
- 要保守，不要因單一關鍵字就判定 HIGH。
- 若有索取密碼、驗證碼、錢包助記詞、銀行資料、異常登入驗證，風險提高。
- 若 URL 與知名品牌相似但網域不一致，風險提高。
- 若資料不足，回傳 LOW 或 MEDIUM，並說明不確定性。
"""


def _safe_json_loads(text: str) -> dict | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _normalize_result(data: dict, fallback: ScanResponse) -> ScanResponse:
    risk = str(data.get("riskLevel", fallback.riskLevel)).upper()
    if risk not in {"LOW", "MEDIUM", "HIGH"}:
        risk = fallback.riskLevel
    try:
        score = int(data.get("score", fallback.score))
    except (TypeError, ValueError):
        score = fallback.score
    score = max(0, min(100, score))
    reasons = data.get("reasons", fallback.reasons)
    if not isinstance(reasons, list):
        reasons = fallback.reasons
    summary = str(data.get("aiSummary", "")).strip() or fallback.aiSummary
    return ScanResponse(riskLevel=risk, score=score, reasons=[str(item) for item in reasons][:8], aiSummary=summary, source="openai-responses-api")


async def analyze_with_ai(payload: ScanRequest) -> ScanResponse:
    settings = get_settings()
    rule_result = check_rules(payload)

    if not settings.openai_api_key:
        return ScanResponse(
            riskLevel=rule_result.riskLevel,
            score=rule_result.score,
            reasons=rule_result.reasons + ["未設定 OPENAI_API_KEY，已改用後端規則結果"],
            aiSummary="後端尚未設定 OpenAI API Key，因此未執行 AI 分析。",
            source="backend-rules-fallback",
        )

    client = AsyncOpenAI(api_key=settings.openai_api_key)
    request_body = {
        "url": payload.url,
        "pageTitle": payload.pageTitle,
        "context": (payload.context or "")[:4000],
        "links": payload.links[:40],
        "localFindings": [item.model_dump() for item in payload.localFindings[:20]],
        "backendRuleResult": rule_result.model_dump(),
    }

    response = await client.responses.create(
        model=settings.openai_model,
        instructions=SYSTEM_PROMPT,
        input=json.dumps(request_body, ensure_ascii=False),
        temperature=0.2,
    )
    text = getattr(response, "output_text", "") or ""
    print(f"{'/'*20}")
    print(f"AI 輸入內容: {request_body}")
    print(f"{'='*20}")
    print(f"AI 回傳內容: {text}")
    print(f"{'/'*20}")
    data = _safe_json_loads(text)
    if not data:
        return ScanResponse(
            riskLevel=rule_result.riskLevel,
            score=rule_result.score,
            reasons=rule_result.reasons + ["AI 回傳內容無法解析，已改用後端規則結果"],
            aiSummary=text[:300] or rule_result.aiSummary,
            source="backend-rules-ai-parse-fallback",
        )
    return _normalize_result(data, rule_result)
