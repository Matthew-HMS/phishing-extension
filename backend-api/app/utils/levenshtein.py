from urllib.parse import urlparse
from Levenshtein import distance

KNOWN_BRANDS = [
    "google", "facebook", "instagram", "gmail", "messenger", "line", "apple",
    "microsoft", "paypal", "netflix", "amazon", "mega", "dropbox", "bank",
]


def brand_impersonation_score(url: str) -> tuple[int, list[str]]:
    host = urlparse(url).hostname or ""
    labels = [label for label in host.lower().split(".") if label]
    reasons: list[str] = []
    score = 0
    for label in labels:
        for brand in KNOWN_BRANDS:
            if label == brand:
                continue
            dist = distance(label, brand)
            if 0 < dist <= 2 and len(label) >= max(4, len(brand) - 1):
                score = max(score, 30)
                reasons.append(f"網域片段「{label}」與知名品牌「{brand}」高度相似")
    return score, reasons[:5]
