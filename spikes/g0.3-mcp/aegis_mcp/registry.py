"""Fake registry + fake session directory for spike G0.3a.

The real M05 registry lives in PostgreSQL (S1.1/S1.2a, migration 0005/0006) and
will enforce idempotency with a unique index.  This module is an in-memory stand
in that keeps the same observable semantics so the MCP layer can be measured and
tested without a database:

* one job per (campaign_id, idempotency_key),
* same key + same scan identity -> ``duplicate`` with the *same* job_id,
* same key + different scan identity or different scheduling -> conflict,
* a per-key lock stands in for the DB unique index (``lock_enabled`` lets tests
  prove the lock is what prevents duplicate jobs).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

CAPABILITY_POPULATION = {
    "dns.enumerate_subdomains": 60,
    "dns.resolve": 25,
    "network.discover_services": 15,
}


def uuid7() -> str:
    """RFC 9562 UUIDv7 (time ordered), matching ids.v2#/$defs/Id."""
    milliseconds = time.time_ns() // 1_000_000
    random_bits = secrets.randbits(74)
    value = (milliseconds & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= (random_bits >> 62) << 64
    value |= 0b10 << 62
    value |= random_bits & ((1 << 62) - 1)
    hexed = f"{value:032x}"
    return f"{hexed[0:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}"


@dataclass(frozen=True)
class Provider:
    name: str
    capability: str
    provider_version: str
    adapter_version: str
    manifest_sha256: str
    image_digest: str
    healthy: bool = True


@dataclass(frozen=True)
class SessionContext:
    campaign_id: str
    session_id: str
    scan_cycle: str


@dataclass(frozen=True)
class Job:
    job_id: str
    campaign_id: str
    session_id: str
    capability: str
    provider: Provider
    input: dict[str, Any]
    priority: int
    depends_on: tuple[str, ...]
    scan_cycle: str
    fingerprint: str
    created_at: float


@dataclass(frozen=True)
class SubmitResult:
    decision: str
    job: Job


class IdempotencyConflict(Exception):
    """Same idempotency_key, different scan identity."""


class SchedulingConflict(Exception):
    """Same job identity, different priority/depends_on."""


@dataclass
class SessionDirectory:
    """Server-side session context; the MCP layer only *compares* it to _meta."""

    known: dict[tuple[str, str], SessionContext] = field(default_factory=dict)
    bound: dict[str, SessionContext] = field(default_factory=dict)

    def register(self, context: SessionContext) -> SessionContext:
        self.known[(context.campaign_id, context.session_id)] = context
        return context

    def resolve(
        self, mcp_session_id: str | None, campaign_id: str, session_id: str
    ) -> tuple[SessionContext | None, str | None]:
        if mcp_session_id is not None:
            bound = self.bound.get(mcp_session_id)
            if bound is not None:
                if (bound.campaign_id, bound.session_id) == (campaign_id, session_id):
                    return bound, None
                return None, "mismatch"
        context = self.known.get((campaign_id, session_id))
        if context is None:
            return None, "unknown"
        if mcp_session_id is not None:
            self.bound[mcp_session_id] = context
        return context, None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class FakeRegistry:
    providers: list[Provider] = field(default_factory=list)
    sessions: SessionDirectory = field(default_factory=SessionDirectory)
    jobs: dict[str, Job] = field(default_factory=dict)
    by_key: dict[tuple[str, str], Job] = field(default_factory=dict)
    lock_enabled: bool = True
    # Simulated write cost inside the critical section (seconds).  0 keeps the
    # idempotency tests fast; the latency benchmark documents what it adds.
    write_latency: float = 0.0
    _locks: dict[tuple[str, str], asyncio.Lock] = field(default_factory=dict)

    @classmethod
    def with_providers(cls, population: dict[str, int] | None = None) -> "FakeRegistry":
        registry = cls()
        for capability, count in (population or CAPABILITY_POPULATION).items():
            for index in range(count):
                registry.providers.append(_provider(capability, index))
        return registry

    # -- registry queries ---------------------------------------------------
    def providers_for(self, capability: str) -> list[Provider]:
        return [provider for provider in self.providers if provider.capability == capability and provider.healthy]

    def choose_provider(self, capability: str) -> Provider | None:
        matches = self.providers_for(capability)
        if not matches:
            return None
        return min(matches, key=lambda provider: (provider.name, provider.provider_version))

    # -- jobs ---------------------------------------------------------------
    def fingerprint(self, *, campaign_id: str, capability: str, provider: Provider, input: dict[str, Any], scan_cycle: str) -> str:
        material = {
            "campaign_id": campaign_id,
            "capability": capability,
            "provider": provider.name,
            "provider_version": provider.provider_version,
            "adapter_version": provider.adapter_version,
            "manifest_sha256": provider.manifest_sha256,
            "image_digest": provider.image_digest,
            "input": input,
            "scan_cycle": scan_cycle,
        }
        return hashlib.sha256(_canonical_json(material).encode()).hexdigest()

    async def submit(
        self,
        *,
        campaign_id: str,
        session_id: str,
        idempotency_key: str,
        capability: str,
        provider: Provider,
        input: dict[str, Any],
        priority: int,
        depends_on: list[str],
        scan_cycle: str,
    ) -> SubmitResult:
        key = (campaign_id, idempotency_key)
        fingerprint = self.fingerprint(
            campaign_id=campaign_id, capability=capability, provider=provider, input=input, scan_cycle=scan_cycle
        )
        scheduling = (priority, tuple(sorted(depends_on)))
        lock = self._locks.setdefault(key, asyncio.Lock())
        if self.lock_enabled:
            async with lock:
                return await self._commit(
                    key=key,
                    fingerprint=fingerprint,
                    scheduling=scheduling,
                    campaign_id=campaign_id,
                    session_id=session_id,
                    capability=capability,
                    provider=provider,
                    input=input,
                    priority=priority,
                    depends_on=depends_on,
                    scan_cycle=scan_cycle,
                )
        return await self._commit(
            key=key,
            fingerprint=fingerprint,
            scheduling=scheduling,
            campaign_id=campaign_id,
            session_id=session_id,
            capability=capability,
            provider=provider,
            input=input,
            priority=priority,
            depends_on=depends_on,
            scan_cycle=scan_cycle,
        )

    async def _commit(
        self,
        *,
        key: tuple[str, str],
        fingerprint: str,
        scheduling: tuple[int, tuple[str, ...]],
        campaign_id: str,
        session_id: str,
        capability: str,
        provider: Provider,
        input: dict[str, Any],
        priority: int,
        depends_on: list[str],
        scan_cycle: str,
    ) -> SubmitResult:
        existing = self.by_key.get(key)
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise IdempotencyConflict(key[1])
            if (existing.priority, existing.depends_on) != (priority, tuple(sorted(depends_on))):
                raise SchedulingConflict(key[1])
            return SubmitResult("duplicate", existing)
        if self.write_latency:
            await asyncio.sleep(self.write_latency)
        job = Job(
            job_id=uuid7(),
            campaign_id=campaign_id,
            session_id=session_id,
            capability=capability,
            provider=provider,
            input=input,
            priority=priority,
            depends_on=tuple(depends_on),
            scan_cycle=scan_cycle,
            fingerprint=fingerprint,
            created_at=time.time(),
        )
        self.jobs[job.job_id] = job
        self.by_key[key] = job
        return SubmitResult("approved", job)

    def jobs_for(self, campaign_id: str) -> list[Job]:
        return [job for job in self.jobs.values() if job.campaign_id == campaign_id]

    def reset(self) -> None:
        self.jobs.clear()
        self.by_key.clear()
        self._locks.clear()


def _provider(capability: str, index: int) -> Provider:
    digest_seed = f"{capability}:{index}".encode()
    return Provider(
        name=f"{capability.replace('.', '-')}-{index:03d}",
        capability=capability,
        provider_version="v2.6.6",
        adapter_version="1.0.0",
        manifest_sha256=hashlib.sha256(digest_seed).hexdigest(),
        image_digest="sha256:" + hashlib.sha256(digest_seed + b":image").hexdigest(),
    )
