"""API router registry: the one place modules add their routers to the M26 app.

G1.1b/G1.1c/G1.5a each own a router module and register it here, so the app factory never needs
to know module names and two tasks never edit the same `create_app`. Registration is explicit and
strict: a duplicate name or prefix fails at start-up instead of silently shadowing routes.
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
    _prefixes: set[str] = field(default_factory=set, init=False)

    def register(self, name: str, router: APIRouter, *, prefix: str = "") -> RouterEntry:
        if not name:
            raise ValueError("router name must not be empty")
        if name in self._names:
            raise ValueError(f"router {name!r} is already registered")
        if prefix in self._prefixes:
            raise ValueError(f"router prefix {prefix!r} is already registered")
        entry = RouterEntry(name=name, router=router, prefix=prefix)
        self._entries.append(entry)
        self._names.add(name)
        self._prefixes.add(prefix)
        return entry

    @property
    def entries(self) -> tuple[RouterEntry, ...]:
        return tuple(self._entries)

    def include_all(self, app: FastAPI) -> None:
        for entry in self._entries:
            app.include_router(entry.router, prefix=entry.prefix)
