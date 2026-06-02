import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_scan_high_risk_url():
    payload = {"url": "http://g00gle-login-security.example.ru/verify/account/password", "context": "請立即重新登入"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 75
    assert data["risk_level"] == "HIGH"
