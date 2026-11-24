"""API router registry, app factory and the fail-closed operator identity seam (OI-4 stub)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from aegis.m26_api.app import API_PREFIX, OPENAPI_PATH, create_app
from aegis.m26_api.operator import (
    OperatorAuthenticationError,
    OperatorAuthenticator,
    Principal,
    RejectingAuthenticator,
    bearer_token,
    require_principal,
)
from aegis.m26_api.registry import RouterRegistry


def _campaigns_router() -> APIRouter:
    router = APIRouter()

    @router.get("/campaigns")
    def list_campaigns() -> list[str]:
        return []

    return router


def test_health_and_openapi_paths() -> None:
    client = TestClient(create_app())
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get(OPENAPI_PATH).status_code == 200


def test_registered_router_is_mounted_under_its_prefix() -> None:
    registry = RouterRegistry()
    registry.register("campaigns", _campaigns_router(), prefix=API_PREFIX)
    app = create_app(registry)

    assert TestClient(app).get(f"{API_PREFIX}/campaigns").json() == []
    assert f"{API_PREFIX}/campaigns" in app.openapi()["paths"]
    assert [entry.name for entry in registry.entries] == ["campaigns"]


def test_duplicate_router_name_or_prefix_is_refused() -> None:
    registry = RouterRegistry()
    registry.register("campaigns", APIRouter(), prefix=API_PREFIX)
    with pytest.raises(ValueError, match="already registered"):
        registry.register("campaigns", APIRouter(), prefix="/other")
    with pytest.raises(ValueError, match="already registered"):
        registry.register("jobs", APIRouter(), prefix=API_PREFIX)
    with pytest.raises(ValueError, match="must not be empty"):
        registry.register("", APIRouter(), prefix="/empty")


class _AcceptingAuthenticator:
    """Test double: a token is accepted and mapped to an opaque principal id."""

    def authenticate(self, authorization: str | None) -> Principal:
        token = bearer_token(authorization)
        return Principal(id=f"principal-of-{len(token)}")


def test_operator_dependency_is_fail_closed_by_default() -> None:
    router = APIRouter()

    @router.get("/protected")
    def protected(principal: Principal = Depends(require_principal)) -> dict[str, str]:
        return {"id": principal.id}

    registry = RouterRegistry()
    registry.register("protected", router, prefix=API_PREFIX)
    client = TestClient(create_app(registry))

    response = client.get(f"{API_PREFIX}/protected", headers={"authorization": "Bearer token"})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_verified_principal_reaches_the_route() -> None:
    router = APIRouter()

    @router.get("/protected")
    def protected(principal: Principal = Depends(require_principal)) -> dict[str, str]:
        return {"id": principal.id, "kind": principal.kind}

    registry = RouterRegistry()
    registry.register("protected", router, prefix=API_PREFIX)
    client = TestClient(create_app(registry, operator_authenticator=_AcceptingAuthenticator()))

    accepted = client.get(f"{API_PREFIX}/protected", headers={"authorization": "Bearer abc"})
    assert accepted.status_code == 200
    assert accepted.json() == {"id": "principal-of-3", "kind": "operator"}
    assert client.get(f"{API_PREFIX}/protected").status_code == 401


def test_bearer_token_parsing() -> None:
    assert bearer_token("Bearer opaque-token") == "opaque-token"
    assert bearer_token("bearer  spaced ") == "spaced"
    for header in (None, "", "Basic abc", "Bearer", "Bearer "):
        with pytest.raises(OperatorAuthenticationError):
            bearer_token(header)


def test_interfaces_are_structural() -> None:
    assert isinstance(RejectingAuthenticator(), OperatorAuthenticator)


def _entries() -> Iterator[str]:
    registry = RouterRegistry()
    registry.register("a", APIRouter(), prefix="/a")
    registry.register("b", APIRouter(), prefix="/b")
    yield from (entry.name for entry in registry.entries)


def test_registry_keeps_registration_order() -> None:
    assert list(_entries()) == ["a", "b"]
