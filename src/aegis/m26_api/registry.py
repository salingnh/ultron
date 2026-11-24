"""API router registry: the one place modules add their routers to the M26 app.

G1.1b/G1.1c/G1.5a each own a router module and register it here, so the app factory never needs
to know module names and two tasks never edit the same `create_app`. Registration is explicit and
strict: a duplicate router name fails at start-up, and so does a route path+method that two routers
both claim. Sharing the `/api/v2` prefix is normal - every module mounts under it - so the prefix
itself is not exclusive; the route paths are.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter, FastAPI

__all__ = ["RouterEntry", "RouterRegistry"]


@dataclass(frozen=True, slots=True)
class RouterEntry:
    """One registered router: a stable name, the router and the mount prefix."""

    name: str
    router: APIRouter
    prefix: str = ""


@dataclass
class RouterRegistry:
    """Ordered collection of routers; `include_all` mounts them on a FastAPI app."""

    _entries: list[RouterEntry] = field(default_factory=list, init=False)
    _names: set[str] = field(default_factory=set, init=False)

    def register(self, name: str, router: APIRouter, *, prefix: str = "") -> RouterEntry:
        if not name:
            raise ValueError("router name must not be empty")
        if name in self._names:
            raise ValueError(f"router {name!r} is already registered")
        entry = RouterEntry(name=name, router=router, prefix=prefix)
        self._entries.append(entry)
        self._names.add(name)
        return entry

    @property
    def entries(self) -> tuple[RouterEntry, ...]:
        return tuple(self._entries)

    def include_all(self, app: FastAPI) -> None:
        self._refuse_route_collisions()
        for entry in self._entries:
            app.include_router(entry.router, prefix=entry.prefix)

    def _refuse_route_collisions(self) -> None:
        """Fail loudly when two routers claim the same path+method (FastAPI keeps the first one)."""
        claimed: dict[tuple[str, str], str] = {}
        for entry in self._entries:
            for route in entry.router.routes:
                path = getattr(route, "path", None)
                methods = getattr(route, "methods", None)
                if not path or not methods:
                    continue
                full_path = f"{entry.prefix}{path}"
                for method in methods:
                    if method in {"HEAD", "OPTIONS"}:
                        continue
                    key = (full_path, method)
                    if key in claimed:
                        raise ValueError(
                            f"route {method} {full_path} is claimed by both "
                            f"{claimed[key]!r} and {entry.name!r}"
                        )
                    claimed[key] = entry.name
