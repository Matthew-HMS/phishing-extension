import math
import re
from collections import Counter
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "account", "password", "secure", "wallet", "bank", "update", "confirm"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "reurl.cc"}
IP_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    text = f"{host}{path}{query}".lower()
    return {
        "scheme": parsed.scheme,
        "host": host,
        "path": path,
        "query": query,
        "url_length": len(url),
        "host_length": len(host),
        "subdomain_count": max(host.count(".") - 1, 0),
        "special_char_count": sum(1 for char in url if not char.isalnum()),
        "entropy": round(shannon_entropy(text), 3),
        "uses_ip_host": bool(IP_HOST_RE.match(host)),
        "is_shortener": host.lower().removeprefix("www.") in SHORTENERS,
        "suspicious_words": [word for word in SUSPICIOUS_WORDS if word in text],
    }
