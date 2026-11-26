"""When an NVD criterion applies to an observed service: the configuration, not the flat list.

NVD publishes affectedness as configurations over `nodes`, not as a flat list of criteria:

    "configurations": [
      {"operator": "AND", "nodes": [
        {"operator": "OR", "negate": false, "cpeMatch": [
          {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:...",
           "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.62"}]},
        {"operator": "OR", "negate": false, "cpeMatch": [
          {"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:..."}]}]}]

M18 also stores the flattened `cpe_match` list, because the PostgreSQL GIN index narrows 400k
revisions by `(part, vendor, product)` with it; the flat list says *which products a CVE mentions*
and cannot say *under which conditions*. Three things in the tree change the decision and were lost
by flattening (G1.6 trial: 14 wrong candidates on httpd 2.4.49, 3 on tomcat 9.0.30):

* `"operator": "AND"` needs every node. CVE-2024-40898 (SSRF in mod_rewrite) is an AND of
  "http_server < 2.4.62" and "microsoft:windows": an Apache on Linux matches the product criterion
  and is still not affected, and nothing in the observations says the host is Windows;
* `"negate": true` inverts its node, and a negated node never confirms a vulnerability;
* `"vulnerable": false` marks a product that is present in the configuration but is **not** the
  vulnerable component - the platform half of a "runs on" node list, or an exclusion. It is never
  a match, whatever version it carries.

On top of that, a criterion without version evidence (`cpe:2.3:a:apache:http_server:-:...`, or
`...:*:...` with no `versionStart*`/`versionEnd*`) does not mean "every version is affected": `-` is
CPE's "not applicable" and `*` is "any", so NVD published no version to compare a banner with. Such
a criterion is UNKNOWN here (the product is present, the version is unconfirmed) and UNKNOWN is not
a candidate - that was the 11 pre-2008 "Apache httpd" CVEs in the trial screenshot.

The evaluation is three-valued over the CPEs one asset actually observed:

* TRUE - the criterion's product is observed and its version is inside the criterion's bounds;
* FALSE - the product was not observed at all, so a configuration that ANDs another product is
  FALSE and correctly produces no candidate;
* UNKNOWN - the product is observed but the criterion carries no version to decide with.

A `Decision.reason` says why a CVE that mentions the observed product became no candidate
(`VERSION_UNSPECIFIED`, `PLATFORM_UNCONFIRMED`), so the matcher can report what it could not decide
instead of silently dropping it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from aegis.m20_vuln.cpe import (
    CompiledCpeMatch,
    Cpe,
    CpeError,
    CpeMatch,
    CpeVersion,
    parse_version,
)

__all__ = [
    "Configuration",
    "Criterion",
    "Decision",
    "Node",
    "Observed",
    "PLATFORM_UNCONFIRMED_CODE",
    "PLATFORM_UNCONFIRMED_MESSAGE",
    "VERSION_UNSPECIFIED_CODE",
    "VERSION_UNSPECIFIED_MESSAGE",
    "Verdict",
    "decide",
    "observe",
    "parse_configurations",
    "products",
]

#: NVD published the product of a criterion with no version and no bound (`-`/`*`).
VERSION_UNSPECIFIED_CODE = "VERSION_UNSPECIFIED"
VERSION_UNSPECIFIED_MESSAGE = "NVD publishes no version for this criterion, not a version match"
#: The configuration ANDs another product (a platform, "runs on") that was never observed.
PLATFORM_UNCONFIRMED_CODE = "PLATFORM_UNCONFIRMED"
PLATFORM_UNCONFIRMED_MESSAGE = (
    "the NVD configuration requires another product that was not observed"
)

_AND = "AND"
_OR = "OR"


class Verdict(StrEnum):
    """Three-valued truth of a criterion, node or configuration against observed CPEs."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Observed:
    """One CPE an asset really carries, with the version the matcher can compare (`None` = none)."""

    cpe: Cpe
    version: CpeVersion | None


def observe(cpes: Iterable[Cpe]) -> tuple[Observed, ...]:
    """Pair every observed CPE with its parsed version; an unusable version stays `None`."""
    observed: list[Observed] = []
    for cpe in cpes:
        version: CpeVersion | None = None
        if cpe.has_version:
            try:
                version = parse_version(cpe.effective_version)
            except CpeError:
                version = None
        observed.append(Observed(cpe=cpe, version=version))
    return tuple(observed)


@dataclass(frozen=True, slots=True)
class _Located:
    """The verdict of one piece of the tree, plus what it did and did not establish."""

    verdict: Verdict
    #: A `vulnerable` criterion for an observed product matched a version.
    confirmed: bool = False
    #: An observed product is here, but the criterion carries no version to decide with.
    unspecified: bool = False
    #: Some criterion of this node names an observed product (an AND node without one is a
    #: requirement on another product, e.g. an operating system).
    observed_product: bool = False
    #: The configuration needs a product the observations could not confirm ("runs on" a platform).
    requires_platform: bool = False
    #: The confirming criterion, so the candidate carries its range and confidence.
    criterion: Criterion | None = None


def _combine(operator: str, verdicts: Sequence[Verdict]) -> Verdict:
    """AND/OR over three-valued verdicts; an empty node establishes nothing."""
    if not verdicts:
        return Verdict.FALSE
    if operator == _AND:
        if Verdict.FALSE in verdicts:
            return Verdict.FALSE
        return Verdict.UNKNOWN if Verdict.UNKNOWN in verdicts else Verdict.TRUE
    if Verdict.TRUE in verdicts:
        return Verdict.TRUE
    return Verdict.UNKNOWN if Verdict.UNKNOWN in verdicts else Verdict.FALSE


def _invert(verdict: Verdict) -> Verdict:
    return {
        Verdict.TRUE: Verdict.FALSE,
        Verdict.FALSE: Verdict.TRUE,
        Verdict.UNKNOWN: Verdict.UNKNOWN,
    }[verdict]


def _best(criteria: Iterable[Criterion | None]) -> Criterion | None:
    """The strongest confirming criterion: an exact version beats a range."""
    strongest: Criterion | None = None
    for criterion in criteria:
        if criterion is None:
            continue
        if strongest is None or (criterion.exact and not strongest.exact):
            strongest = criterion
    return strongest


@dataclass(frozen=True, slots=True)
class Criterion:
    """One `cpeMatch` entry: a product, its version bounds and whether it is vulnerable."""

    compiled: CompiledCpeMatch
    vulnerable: bool

    @classmethod
    def from_json(cls, entry: object) -> Criterion:
        if not isinstance(entry, dict):
            raise CpeError(f"a cpeMatch entry must be an object: {entry!r}")
        return cls(
            compiled=CompiledCpeMatch.compile(CpeMatch.from_json(entry)),
            vulnerable=bool(entry.get("vulnerable", False)),
        )

    @property
    def target(self) -> Cpe:
        return self.compiled.target

    @property
    def exact(self) -> bool:
        return self.compiled.exact

    @property
    def range_text(self) -> str | None:
        return self.compiled.range_text

    def evaluate(self, observed: Sequence[Observed]) -> _Located:
        same = [
            item
            for item in observed
            if item.cpe.part == self.target.part and item.cpe.product_key == self.target.product_key
        ]
        if not same:
            return _Located(Verdict.FALSE)
        if not self.compiled.version_evidence:
            if not self.vulnerable:
                # "present, but not the vulnerable component": presence is the whole statement, so
                # the platform half of a "runs on" node is satisfied without a version to compare.
                return _Located(Verdict.TRUE, observed_product=True)
            return _Located(Verdict.UNKNOWN, unspecified=True, observed_product=True)
        hit = any(
            item.version is not None and self.compiled.matches_parsed(item.cpe, item.version)
            for item in same
        )
        confirmed = bool(hit and self.vulnerable)
        return _Located(
            Verdict.TRUE if hit else Verdict.FALSE,
            confirmed=confirmed,
            observed_product=True,
            criterion=self if confirmed else None,
        )


@dataclass(frozen=True, slots=True)
class Node:
    """One NVD node: its criteria and children combined by `operator`, then optionally negated."""

    operator: str
    negate: bool
    criteria: tuple[Criterion, ...] = ()
    children: tuple[Node, ...] = ()

    @classmethod
    def from_json(cls, entry: object) -> Node | None:
        if not isinstance(entry, dict):
            return None
        # M18 stores `cpe_match`; a raw NVD document spells it `cpeMatch`. Both are readable here.
        raw = entry.get("cpe_match")
        if not isinstance(raw, list):
            raw = entry.get("cpeMatch")
        criteria: list[Criterion] = []
        for item in raw or ():
            try:
                criteria.append(Criterion.from_json(item))
            except (CpeError, KeyError):
                continue  # a criterion this matcher cannot read is skipped, not guessed
        children: list[Node] = []
        for child in entry.get("children") or ():
            parsed = cls.from_json(child)
            if parsed is not None:
                children.append(parsed)
        if not criteria and not children:
            return None
        return cls(
            operator=_operator(entry.get("operator")),
            negate=bool(entry.get("negate")),
            criteria=tuple(criteria),
            children=tuple(children),
        )

    def evaluate(self, observed: Sequence[Observed]) -> _Located:
        results = [criterion.evaluate(observed) for criterion in self.criteria]
        results.extend(child.evaluate(observed) for child in self.children)
        verdict = _combine(self.operator, [result.verdict for result in results])
        observed_product = any(result.observed_product for result in results)
        if self.negate:
            # "not this node" is never a confirmation: the node says what is *not* there.
            return _Located(_invert(verdict), observed_product=observed_product)
        confirmed = any(result.confirmed for result in results)
        return _Located(
            verdict,
            confirmed=confirmed,
            unspecified=any(result.unspecified for result in results),
            observed_product=observed_product,
            requires_platform=_names_another_product(self.operator, results)
            or any(result.requires_platform for result in results),
            criterion=(
                _best(result.criterion for result in results)
                if confirmed and verdict is Verdict.TRUE
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class Configuration:
    """One NVD configuration: its nodes combined by `operator` (`AND` only when NVD says so)."""

    operator: str
    nodes: tuple[Node, ...]

    @classmethod
    def from_json(cls, entry: object) -> Configuration | None:
        if not isinstance(entry, dict):
            return None
        nodes = [Node.from_json(node) for node in entry.get("nodes") or ()]
        kept = tuple(node for node in nodes if node is not None)
        if not kept:
            return None
        return cls(operator=_operator(entry.get("operator")), nodes=kept)

    def evaluate(self, observed: Sequence[Observed]) -> _Located:
        results = [node.evaluate(observed) for node in self.nodes]
        verdict = _combine(self.operator, [result.verdict for result in results])
        confirmed = any(result.confirmed for result in results)
        return _Located(
            verdict,
            confirmed=confirmed,
            unspecified=any(result.unspecified for result in results),
            observed_product=any(result.observed_product for result in results),
            requires_platform=_names_another_product(self.operator, results)
            or any(result.requires_platform for result in results),
            criterion=(
                _best(result.criterion for result in results)
                if confirmed and verdict is Verdict.TRUE
                else None
            ),
        )


def _names_another_product(operator: str, results: Sequence[_Located]) -> bool:
    """True when an AND needs a product the observations never carried ("runs on Windows").

    The configuration then says "affected when it runs on X": the product criterion can be
    satisfied and the CVE still does not apply to what was observed, which is why this is reported
    as undecided (`PLATFORM_UNCONFIRMED`) rather than as a candidate or as a clean non-match.
    """
    if operator != _AND or len(results) < 2:
        return False
    return any(not result.observed_product for result in results)


@dataclass(frozen=True, slots=True)
class Decision:
    """What the matcher decided for one CVE against one asset's observed CPEs."""

    verdict: Verdict
    criterion: Criterion | None = None
    #: Why a CVE that names an observed product became no candidate (`None` when it is unrelated).
    reason: str | None = None

    @property
    def matched(self) -> bool:
        return self.criterion is not None


def decide(configurations: Sequence[Configuration], observed: Sequence[Observed]) -> Decision:
    """TRUE (with the confirming criterion) when any configuration is satisfied, else why not."""
    unspecified = False
    platform = False
    for configuration in configurations:
        result = configuration.evaluate(observed)
        if result.verdict is Verdict.TRUE and result.confirmed and result.criterion is not None:
            return Decision(Verdict.TRUE, result.criterion)
        if result.unspecified:
            unspecified = True
        elif result.confirmed and result.requires_platform:
            platform = True
    if unspecified:
        return Decision(Verdict.UNKNOWN, reason=VERSION_UNSPECIFIED_CODE)
    if platform:
        return Decision(Verdict.UNKNOWN, reason=PLATFORM_UNCONFIRMED_CODE)
    return Decision(Verdict.FALSE)


def parse_configurations(affected: object) -> tuple[Configuration, ...]:
    """The stored `affected` document as configurations, old flat rows included.

    A revision synced before M18 stored the tree has only `cpe_match`. Each of its criteria then
    becomes its own one-node configuration: the same OR semantics as the flat list, without the
    conditions the feed threw away (and without matching an unbounded criterion to any version).
    """
    document = affected if isinstance(affected, dict) else {}
    tree = document.get("configurations")
    if isinstance(tree, list):
        configurations = [Configuration.from_json(entry) for entry in tree]
        kept = tuple(item for item in configurations if item is not None)
        if kept:
            return kept
    return _flat_configurations(document.get("cpe_match"))


def _flat_configurations(entries: object) -> tuple[Configuration, ...]:
    if not isinstance(entries, list):
        return ()
    configurations: list[Configuration] = []
    for entry in entries:
        try:
            criterion = Criterion.from_json(entry)
        except (CpeError, KeyError):
            continue
        configurations.append(
            Configuration(
                operator=_OR, nodes=(Node(operator=_OR, negate=False, criteria=(criterion,)),)
            )
        )
    return tuple(configurations)


def _operator(value: object) -> str:
    return _AND if isinstance(value, str) and value.strip().upper() == _AND else _OR


def _product_keys(configurations: Sequence[Configuration]) -> set[tuple[str, str]]:
    """Every product the configurations mention, as `(vendor, product)` buckets."""
    keys: set[tuple[str, str]] = set()

    def visit(node: Node) -> None:
        for criterion in node.criteria:
            keys.add(criterion.target.product_key)
        for child in node.children:
            visit(child)

    for configuration in configurations:
        for node in configuration.nodes:
            visit(node)
    return keys


def products(configurations: Sequence[Configuration]) -> frozenset[tuple[str, str]]:
    """The `(vendor, product)` buckets a revision can be narrowed to."""
    return frozenset(_product_keys(configurations))
