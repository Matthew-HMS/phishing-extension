from app.schemas.scan import ScanRequest, ScanResponse
from app.utils.url_features import extract_url_features


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def risk_from_score(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def check_rules(payload: ScanRequest) -> ScanResponse:
    features = extract_url_features(payload.url)
    score = 0
    reasons: list[str] = []

    if features["scheme"] != "https":
        score += 20
        reasons.append("URL 未使用 HTTPS")
    if features["uses_ip_host"]:
        score += 35
        reasons.append("網域使用 IP 位址，常見於臨時釣魚站")
    if features["is_shortener"]:
        score += 25
        reasons.append("使用短網址，實際目的地不透明")
    if features["url_length"] > 120:
        score += 15
        reasons.append("URL 長度異常偏長")
    if features["subdomain_count"] >= 3:
        score += 15
        reasons.append("子網域層級過多")
    if features["entropy"] >= 4.2:
        score += 15
        reasons.append("URL 字元熵值偏高，可能有混淆或隨機產生特徵")
    if features["suspicious_words"]:
        score += min(30, len(features["suspicious_words"]) * 10)
        reasons.append("包含敏感關鍵字：" + ", ".join(features["suspicious_words"]))

    local_high = [item for item in payload.localFindings if item.riskLevel == "HIGH"]
    local_medium = [item for item in payload.localFindings if item.riskLevel == "MEDIUM"]
    if local_high:
        score += 20
        reasons.append("插件本地規則已偵測到高風險連結")
    elif local_medium:
        score += 10
        reasons.append("插件本地規則已偵測到可疑連結")

    score = clamp_score(score)
    return ScanResponse(riskLevel=risk_from_score(score), score=score, reasons=reasons, aiSummary="尚未執行 AI 語意分析", source="backend-rules")
