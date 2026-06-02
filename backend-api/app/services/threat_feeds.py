from __future__ import annotations

from urllib.parse import urlparse

# 原型用本地清單；正式環境可改為排程同步 165、PhishTank 或企業情資來源。
KNOWN_BAD_DOMAINS = {
    "phishing.example.com",
    "g00gle-login-security.example.ru",
    "paypal-secure-update-login.example.com",
}

KNOWN_SAFE_DOMAINS = {
    "google.com",
    "mail.google.com",
    "facebook.com",
    "messenger.com",
    "github.com",
    "openai.com",
}


def normalize_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip(".")


def match_known_lists(url: str) -> tuple[int, list[str]]:
    host = normalize_host(url)
    if host in KNOWN_BAD_DOMAINS:
        return 80, ["命中已知威脅網域清單"]
    if host in KNOWN_SAFE_DOMAINS or any(host.endswith("." + safe) for safe in KNOWN_SAFE_DOMAINS):
        return 0, ["命中本地白名單"]
    return 0, []
