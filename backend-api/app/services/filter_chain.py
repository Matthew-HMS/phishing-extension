from __future__ import annotations

from urllib.parse import urlparse

from app.config import get_settings
from app.models.anomaly import anomaly_detector
from app.schemas.scan import EvidenceItem, RiskLevel, ScanResponse
from app.services.llm_guard import analyze_with_llm
from app.services.threat_feeds import match_known_lists
from app.utils.levenshtein import brand_impersonation_score
from app.utils.url_features import extract_features


def clamp(value: int, lower: int = 0, upper: int = 100) -> int:
    return max(lower, min(upper, value))


def level_for_score(score: int) -> RiskLevel:
    settings = get_settings()
    if score >= settings.high_risk_threshold:
        return RiskLevel.HIGH
    if score >= settings.warning_risk_threshold:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def action_for_level(level: RiskLevel) -> str:
    if level == RiskLevel.HIGH:
        return "BLOCK_AND_WARN"
    if level == RiskLevel.MEDIUM:
        return "WARN_USER"
    return "ALLOW"


async def scan_url(url: str, context: str = "") -> ScanResponse:
    score = 0
    reasons: list[str] = []
    evidence: list[EvidenceItem] = []

    list_score, list_reasons = match_known_lists(url)
    if list_reasons:
        reasons.extend(list_reasons)
        evidence.append(EvidenceItem(module="threat_feeds", message="; ".join(list_reasons), score_delta=list_score))
        score += list_score

    features = extract_features(url)
    feature_score = 0
    feature_messages: list[str] = []
    if features.has_ip_host:
        feature_score += 20
        feature_messages.append("主機使用 IP 位址而非正常網域")
    if features.has_at_symbol:
        feature_score += 25
        feature_messages.append("URL 含 @ 符號，可能用於混淆實際網域")
    if features.punycode:
        feature_score += 25
        feature_messages.append("網域含 Punycode，可能存在同形異義字攻擊")
    if features.length > 120:
        feature_score += 12
        feature_messages.append("URL 長度異常偏長")
    if features.subdomain_count >= 3:
        feature_score += 10
        feature_messages.append("子網域層級過多")
    if features.suspicious_keyword_count >= 2:
        feature_score += 15
        feature_messages.append("URL 含多個登入、驗證或付款相關關鍵字")
    if features.entropy > 4.7:
        feature_score += 10
        feature_messages.append("URL 字元熵值偏高，可能為隨機產生")
    if feature_score:
        feature_score = clamp(feature_score, 0, 45)
        reasons.extend(feature_messages)
        evidence.append(EvidenceItem(module="url_features", message="; ".join(feature_messages), score_delta=feature_score))
        score += feature_score

    brand_score, brand_reasons = brand_impersonation_score(url)
    if brand_score:
        reasons.extend(brand_reasons)
        evidence.append(EvidenceItem(module="brand_impersonation", message="; ".join(brand_reasons), score_delta=brand_score))
        score += brand_score

    ml_score, ml_reason = anomaly_detector.score(url)
    if ml_score:
        reasons.append(ml_reason)
        evidence.append(EvidenceItem(module="ml_anomaly", message=ml_reason, score_delta=ml_score))
        score += ml_score

    llm_result = await analyze_with_llm(url, context)
    if llm_result:
        llm_score = int(llm_result.get("risk_score", 0))
        score = max(score, llm_score)
        llm_reasons = [str(reason) for reason in llm_result.get("reasons", [])][:5]
        reasons.extend(llm_reasons)
        evidence.append(EvidenceItem(module="llm", message="; ".join(llm_reasons) or "LLM completed", score_delta=llm_score))

    parsed = urlparse(url)
    if parsed.scheme != "https":
        score += 10
        reasons.append("未使用 HTTPS")
        evidence.append(EvidenceItem(module="ssl_static", message="未使用 HTTPS", score_delta=10))

    final_score = clamp(score)
    level = level_for_score(final_score)
    if not reasons:
        reasons.append("未發現明顯釣魚特徵")

    return ScanResponse(
        url=url,
        risk_score=final_score,
        risk_level=level,
        reasons=list(dict.fromkeys(reasons))[:8],
        evidence=evidence,
        recommended_action=action_for_level(level),
        cached=False,
    )
