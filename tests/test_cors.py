"""Browser access to the API: an explicit CORS allowlist, never a wildcard.

`make run-local` starts the API for the Vite dev server, which is a different origin. The app
accepts an allowlist of origins (`AEGIS_CORS_ORIGINS` / `create_app(cors_origins=...)`) and adds the
CORS middleware only when that list is non-empty. The operator token travels in a header, so a
wildcard would let any page read the API with the user's token: the allowlist is the point, and an
unlisted origin must get no `Access-Control-Allow-Origin` at all.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from aegis.m26_api.app import (
    API_PREFIX,
    CORS_HEADERS,
    CORS_ORIGINS_ENV,
    cors_origins_from_env,
    create_app,
)
from aegis.m26_api.registry import RouterRegistry

VITE = "http://127.0.0.1:5173"
OTHER_VITE = "http://localhost:5173"
FOREIGN = "https://evil.example"


@pytest.fixture()
def app_client() -> Iterator[TestClient]:
    router = APIRouter()

    @router.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "1"}

    registry = RouterRegistry()
    registry.register("ping", router, prefix=API_PREFIX)
    yield TestClient(create_app(registry, cors_origins=[VITE, OTHER_VITE]))


def test_an_unlisted_origin_gets_no_cors_answer(app_client: TestClient) -> None:
    response = app_client.get(f"{API_PREFIX}/ping", headers={"origin": FOREIGN})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_a_listed_origin_is_echoed_on_a_real_request(app_client: TestClient) -> None:
    response = app_client.get(f"{API_PREFIX}/ping", headers={"origin": VITE})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == VITE
    exposed = response.headers["access-control-expose-headers"].lower()
    assert {"traceparent", "idempotent-replayed", "x-aegis-consumer"} <= {
        header.strip() for header in exposed.split(",")
    }


def test_a_preflight_names_the_headers_the_client_needs(app_client: TestClient) -> None:
    response = app_client.options(
        f"{API_PREFIX}/ping",
        headers={
            "origin": OTHER_VITE,
            "access-control-request-method": "POST",
            "access-control-request-headers": "authorization,idempotency-key,last-event-id",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == OTHER_VITE
    allowed = response.headers["access-control-allow-headers"].lower()
    assert {"authorization", "idempotency-key", "last-event-id"} <= {
        header.strip() for header in allowed.split(",")
    }
    assert response.headers["access-control-allow-methods"] == "GET, POST"


def test_without_an_allowlist_no_cors_middleware_is_installed() -> None:
    router = APIRouter()

    @router.get("/ping")
    def ping() -> dict[str, str]:
        return {"pong": "1"}

    registry = RouterRegistry()
    registry.register("ping", router, prefix=API_PREFIX)
    app = create_app(registry)
    assert not any("CORSMiddleware" in repr(middleware) for middleware in app.user_middleware)
    response = TestClient(app).get(f"{API_PREFIX}/ping", headers={"origin": VITE})
    assert "access-control-allow-origin" not in response.headers


def test_the_origin_list_comes_from_one_comma_separated_variable() -> None:
    assert cors_origins_from_env({}) == []
    assert cors_origins_from_env({CORS_ORIGINS_ENV: "  "}) == []
    assert cors_origins_from_env({CORS_ORIGINS_ENV: f"{VITE}, {OTHER_VITE} ,"}) == [
        VITE,
        OTHER_VITE,
    ]
    assert set(CORS_HEADERS) >= {"Authorization", "Idempotency-Key", "Last-Event-ID"}
