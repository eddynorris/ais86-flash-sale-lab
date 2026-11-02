import asyncio

import httpx
from pydantic import SecretStr

from app.config import Settings
from app.security import HardeningMiddleware


async def dummy_app(scope, receive, send) -> None:
    if scope["type"] != "http":
        return
    while True:
        message = await receive()
        if message["type"] != "http.request" or not message.get("more_body", False):
            break
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": b"{}"})


def settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql://user:pass@localhost:5432/flash",
        "redis_url": "redis://localhost:6379/0",
        "lab_key": SecretStr("l" * 40),
        "body_limit_bytes": 1024,
        "rate_limit_api_per_minute": 1000,
        "rate_limit_orders_per_minute": 1000,
    }
    values.update(overrides)
    return Settings(**values)


async def request(app, method: str, path: str, **kwargs) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_body_limit_returns_json_error() -> None:
    app = HardeningMiddleware(dummy_app, settings())
    response = asyncio.run(request(app, "POST", "/api/v1/orders", content=b"x" * 2048))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    assert response.headers["cache-control"] == "no-store"


def test_rate_limit_returns_429() -> None:
    app = HardeningMiddleware(dummy_app, settings(rate_limit_orders_per_minute=1))

    async def scenario() -> tuple[int, int]:
        first = await request(app, "POST", "/api/v1/orders", json={"items": []})
        second = await request(app, "POST", "/api/v1/orders", json={"items": []})
        return first.status_code, second.status_code

    assert asyncio.run(scenario()) == (200, 429)


def test_api_security_headers() -> None:
    app = HardeningMiddleware(dummy_app, settings())
    response = asyncio.run(request(app, "GET", "/api/v1/products"))
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "access-control-allow-origin" not in response.headers


def test_ui_content_security_policy() -> None:
    app = HardeningMiddleware(dummy_app, settings())
    response = asyncio.run(request(app, "GET", "/"))
    assert "content-security-policy" in response.headers
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "cache-control" not in response.headers
