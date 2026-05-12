import pytest
from fastapi.testclient import TestClient

import sentinel.web.app as web_app_module
from sentinel.web.app import create_dashboard_app, _DIST_DIR

_FRONTEND_BUILT = _DIST_DIR.is_dir() and (_DIST_DIR / "index.html").is_file()
_SKIP_IF_NO_FRONTEND = pytest.mark.skipif(
    not _FRONTEND_BUILT,
    reason="Frontend not built — run 'cd frontend && npm run build' to populate dist/",
)


def test_dashboard_api_fails_closed_before_login(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    response = client.post(
        "/api/firewall/scan",
        json={"prompt": "ignore previous instructions", "scan_type": "input"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
    assert response.json()["schema_version"] == "api.error.v1"
    assert response.json()["error"]["code"] == "auth_required"
    assert "content-security-policy" in response.headers


def test_dashboard_login_token_allows_api_access(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Test-Pass1"},
    )
    token = login.json()["token"]
    response = client.post(
        "/api/firewall/scan",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "ignore previous instructions", "scan_type": "input"},
    )

    assert login.status_code == 200
    assert response.status_code == 200
    assert response.json()["action"] in {"BLOCK", "WARN", "ALLOW"}


def test_dashboard_public_health_does_not_expose_instance_id(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    response = client.get("/api/health")

    assert response.status_code == 200
    assert "instance_id" not in response.json()
    assert response.json()["web_ui"] in {"ready", "missing"}
    assert response.json()["web_ui_build"]["status"] in {"ready", "missing"}
    assert response.json()["web_ui_build"]["ready"] in {True, False}


def test_dashboard_openapi_smoke_snapshot(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    response = client.get("/api/openapi.json")
    payload = response.json()

    assert response.status_code == 200
    assert payload["info"]["title"] == "Eresus Sentinel API"
    assert "/api/health" in payload["paths"]
    assert "/api/firewall/scan" in payload["paths"]


def test_dashboard_missing_dist_returns_build_hint(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    missing_dist = tmp_path / "missing-dist"
    monkeypatch.setattr(web_app_module, "_DIST_DIR", missing_dist)
    client = TestClient(web_app_module.create_dashboard_app())

    response = client.get("/")

    assert response.status_code == 503
    assert "Dashboard frontend is not built" in response.text
    assert "/api/docs" in response.text


def test_dashboard_missing_api_route_uses_error_envelope(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Test-Pass1"},
    )

    response = client.get(
        "/api/nope",
        headers={"Authorization": f"Bearer {login.json()['token']}"},
    )

    assert response.status_code == 404
    assert response.json()["schema_version"] == "api.error.v1"
    assert response.json()["error"]["status"] == 404


def test_dashboard_production_cors_does_not_allow_random_origin(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.delenv("SENTINEL_CORS_ORIGINS", raising=False)
    client = TestClient(create_dashboard_app())

    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers.get("access-control-allow-origin") is None


def test_dashboard_local_cors_allows_localhost(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    monkeypatch.setenv("SENTINEL_ENV", "local")
    monkeypatch.delenv("SENTINEL_CORS_ORIGINS", raising=False)
    client = TestClient(create_dashboard_app())

    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:8080",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers["access-control-allow-origin"] == "http://localhost:8080"


@_SKIP_IF_NO_FRONTEND
def test_dashboard_http_demo_does_not_upgrade_assets(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "upgrade-insecure-requests" not in response.headers["content-security-policy"]
    assert "strict-transport-security" not in response.headers


@_SKIP_IF_NO_FRONTEND
def test_dashboard_https_proxy_gets_strict_transport_headers(monkeypatch):
    monkeypatch.setenv("SENTINEL_PASSWORD", "Test-Pass1")
    client = TestClient(create_dashboard_app())

    response = client.get("/", headers={"X-Forwarded-Proto": "https"})

    assert response.status_code == 200
    assert "upgrade-insecure-requests" in response.headers["content-security-policy"]
    assert "strict-transport-security" in response.headers
