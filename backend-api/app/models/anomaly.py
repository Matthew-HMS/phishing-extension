from __future__ import annotations

import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from app.utils.url_features import extract_features

NORMAL_URLS = [
    "https://www.google.com/search?q=security",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.facebook.com/messages/",
    "https://www.microsoft.com/zh-tw/security",
    "https://github.com/openai/openai-python",
    "https://www.apple.com/tw/support/",
    "https://www.paypal.com/tw/home",
]

MALICIOUS_LIKE_URLS = [
    "http://g00gle-login-security.example.ru/verify/account/password",
    "https://paypal-secure-update-login.example.com/session/reset",
    "http://192.168.99.10/account/verify?token=abc123999",
    "https://faceb00k-messenger-auth.example.net/login",
    "https://xn--pple-43d.example/phishing/login",
]


class UrlAnomalyDetector:
    def __init__(self) -> None:
        samples = [extract_features(url).vector() for url in NORMAL_URLS + MALICIOUS_LIKE_URLS]
        self.scaler = StandardScaler()
        scaled = self.scaler.fit_transform(samples)
        self.model = KMeans(n_clusters=2, random_state=42, n_init="auto")
        self.model.fit(scaled)
        normal_scaled = self.scaler.transform([extract_features(url).vector() for url in NORMAL_URLS])
        labels = self.model.predict(normal_scaled)
        self.normal_cluster = int(np.bincount(labels).argmax())
        self.normal_centroid = self.model.cluster_centers_[self.normal_cluster]
        self.distance_threshold = float(np.percentile(np.linalg.norm(normal_scaled - self.normal_centroid, axis=1), 90) + 2.0)

    def score(self, url: str) -> tuple[int, str]:
        vector = self.scaler.transform([extract_features(url).vector()])[0]
        cluster = int(self.model.predict([vector])[0])
        distance = float(np.linalg.norm(vector - self.normal_centroid))
        if cluster != self.normal_cluster:
            return 35, "URL 特徵落入異常群集"
        if distance > self.distance_threshold:
            return 25, f"URL 特徵距離正常群集過遠，距離={distance:.2f}"
        return 0, "URL 特徵位於正常群集範圍"


anomaly_detector = UrlAnomalyDetector()
