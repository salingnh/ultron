#!/usr/bin/env python3
"""Keep the lab inventory, zone, fixtures and image pins in one story (G0.4c).

`deploy/lab/inventory.json` is the authorized target set. The zone CoreDNS serves, the probe
list dnsx is compared against, the passive-source response and the expected Subfinder hosts
are separate artifacts on purpose (a fixture derived from the code under test proves
nothing), so this checker fails when any of them drifts from the inventory:

  * zone records (A/AAAA/CNAME/MX/TXT/NS) equal the inventory record set;
  * `fixtures/targets.txt` is exactly the probe hosts, and the dnsx expectation for every
    probe matches the zone (CNAME chains resolved, NXDOMAIN/REFUSED have no records);
  * the passive fixture yields exactly the inventory's passive names through the zone filter
    Subfinder applies (wildcards and out-of-zone names dropped);
  * `fixtures/subfinder.expected.json` lists exactly those names;
  * every image in `deploy/lab/images.env` is the ref recorded in the inventory.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

LAB = Path(__file__).resolve().parents[2] / "deploy" / "lab"
INVENTORY = LAB / "inventory.json"
ZONE_FILE = LAB / "dns" / "lab.aegis.test.zone"
TARGETS = LAB / "fixtures" / "targets.txt"
DNSX_EXPECTED = LAB / "fixtures" / "dnsx.expected.json"
SUBFINDER_EXPECTED = LAB / "fixtures" / "subfinder.expected.json"
IMAGES = LAB / "images.env"

RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA"}
DNSX_TYPES = {"A", "AAAA", "CNAME"}
ENV_NAMES = {
    "dns": "AEGIS_LAB_DNS_IMAGE",
    "passive": "AEGIS_LAB_PASSIVE_IMAGE",
    "dnsx": "AEGIS_LAB_DNSX_IMAGE",
    "subfinder": "AEGIS_LAB_SUBFINDER_IMAGE",
    "naabu": "AEGIS_LAB_NAABU_IMAGE",
    "web-legacy": "AEGIS_LAB_WEB_LEGACY_IMAGE",
    "app": "AEGIS_LAB_APP_IMAGE",
    "ssh": "AEGIS_LAB_SSH_IMAGE",
    "cache": "AEGIS_LAB_CACHE_IMAGE",
}


def strip_comment(line: str) -> str:
    out, quoted = [], False
    for char in line:
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            break
        out.append(char)
    return "".join(out)


def tokenize(line: str) -> list[str]:
    return re.findall(r'"(?:[^"]*)"|\S+', line)


def unquote(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def parse_zone(path: Path) -> tuple[str, set[tuple[str, str, str]]]:
    origin = ""
    soa = False
    last_name = ""
    records: set[tuple[str, str, str]] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = strip_comment(raw).strip()
        if not line:
            continue
        if line.upper().startswith("$ORIGIN"):
            origin = line.split()[1].rstrip(".") + "."
            continue
        if line.upper().startswith("$TTL"):
            continue
        if soa:
            if ")" in line:
                soa = False
            continue
        tokens = tokenize(line)
        # Structurally find where the record data starts: owner [ttl] [class] type rdata.
        # A type name can also be the owner (e.g. `txt`), so the first token is not searched.
        index = 0 if raw[:1].isspace() else 1
        if index < len(tokens) and re.fullmatch(r"\d+[smhdwSMHDW]?", tokens[index]):
            index += 1
        if index < len(tokens) and tokens[index].upper() in ("IN", "CH", "HS"):
            index += 1
        if index >= len(tokens) or tokens[index].upper() not in RECORD_TYPES:
            continue
        kind = tokens[index].upper()
        data = tokens[index + 1 :]
        # A line that starts with whitespace omits the owner (repeat the previous one),
        # which is how the apex NS record below the SOA is written.
        if raw[:1].isspace():
            name = last_name or "@"
        else:
            name = tokens[0]
            last_name = name
        if kind == "SOA":
            if "(" in line:
                soa = True
            continue
        if not origin:
            raise SystemExit(f"{path}: record before $ORIGIN: {raw}")
        if name == "@":
            fqdn = origin
        elif name.endswith("."):
            fqdn = name
        else:
            fqdn = f"{name}.{origin}"
        if kind in ("A", "AAAA"):
            value = data[0]
        elif kind in ("CNAME", "NS"):
            target = data[0]
            value = target if target.endswith(".") else f"{target}.{origin}"
        elif kind == "MX":
            target = data[-1]
            target = target if target.endswith(".") else f"{target}.{origin}"
            value = f"{data[0]} {target}"
        elif kind == "TXT":
            value = "".join(unquote(token) for token in data)
        else:
            value = " ".join(data)
        records.add((fqdn.lower(), kind, value))
    if not origin:
        raise SystemExit(f"{path}: no $ORIGIN")
    return origin, records


def records_by_name(records: set[tuple[str, str, str]]) -> dict[str, dict[str, list[str]]]:
    index: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for name, kind, value in records:
        index[name][kind].append(value)
    return index


def expected_for(host: str, index: dict[str, dict[str, list[str]]]) -> dict:
    """What DNSx returns for one name: A/AAAA (CNAME chain resolved) plus the CNAME itself."""
    current = host.lower().rstrip(".") + "."
    chain: list[str] = []
    seen: set[str] = set()
    while True:
        cname = index.get(current, {}).get("CNAME", [])
        if not cname:
            break
        target = cname[0]
        chain.append(target.rstrip("."))
        if target in seen:
            break
        seen.add(target)
        current = target
    return {
        "cname": sorted(chain),
        "a": sorted(index.get(current, {}).get("A", [])),
        "aaaa": sorted(index.get(current, {}).get("AAAA", [])),
    }


def parse_images() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in IMAGES.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def check_services(
    inventory: dict, index: dict[str, dict[str, list[str]]], images: dict[str, str]
) -> list[str]:
    """The G1.6a service containers: one story between inventory, zone and image pins.

    Each entry names a host, the container address, the image key that serves it and the ports it
    answers on. The host must resolve (A record) to exactly that address in the zone, the image key
    must exist in `images` (and therefore in `images.env`), and the ports must be real port numbers;
    the probe list must cover the name too, so `make lab-check` queries it.
    """
    problems: list[str] = []
    services = inventory.get("services") or []
    if not services:
        return ["inventory has no services: the G1.6a lab containers would be untracked"]
    for service in services:
        host = str(service.get("host", "")).lower()
        address = str(service.get("address", ""))
        image = str(service.get("image", ""))
        host_fqdn = host if host.endswith(".") else host + "."
        answers = sorted(index.get(host_fqdn, {}).get("A", []))
        if answers != [address]:
            problems.append(
                f"service {host}: zone A records {answers} do not match the inventory address "
                f"{address!r}"
            )
        if image not in inventory["images"]:
            problems.append(f"service {host}: image key {image!r} is not in inventory images")
        elif image not in ENV_NAMES or ENV_NAMES[image] not in images:
            problems.append(f"service {host}: image key {image!r} has no images.env pin")
        ports = service.get("ports") or []
        if not ports or not all(isinstance(port, int) and 1 <= port <= 65535 for port in ports):
            problems.append(
                f"service {host}: ports {ports!r} are not a non-empty list of port numbers"
            )
    return problems


def check_naabu_fixture(inventory: dict) -> list[str]:
    """`fixtures/naabu.expected.json` is derived from the inventory's services, not from a run."""
    path = LAB / "fixtures" / "naabu.expected.json"
    if not path.is_file():
        return ["missing deploy/lab/fixtures/naabu.expected.json: make lab-naabu compares a run to it"]
    expected = json.loads(path.read_text(encoding="utf-8"))
    ports = [int(port) for port in expected.get("ports") or []]
    services = inventory.get("services") or []
    problems: list[str] = []
    if not ports:
        problems.append("naabu fixture has no port list")
    derived_targets = sorted({str(service["address"]) for service in services})
    if sorted(expected.get("targets") or []) != derived_targets:
        problems.append(
            f"naabu fixture targets {sorted(expected.get('targets') or [])} do not match the "
            f"inventory service addresses {derived_targets}"
        )
    derived_open = sorted(
        (str(service["address"]), int(port), "tcp")
        for service in services
        for port in service.get("ports") or []
        if int(port) in ports
    )
    fixture_open = sorted(
        (str(item["ip"]), int(item["port"]), str(item["protocol"]))
        for item in expected.get("open") or []
    )
    if fixture_open != derived_open:
        problems.append(
            f"naabu fixture open ports {fixture_open} do not match the inventory {derived_open}"
        )
    negative = expected.get("negative_control") or {}
    if negative.get("port") in [port for _, port, _ in derived_open]:
        problems.append(f"naabu fixture negative control {negative.get('port')} is an open service port")
    return problems


def passive_names(zone: str, fixture: Path) -> set[str]:
    zone = zone.rstrip(".")
    names: set[str] = set()
    for record in json.loads(fixture.read_text(encoding="utf-8")):
        for field in ("common_name", "name_value"):
            for name in str(record.get(field, "")).splitlines():
                name = name.strip().lower()
                if name.startswith("*.") or name == zone:
                    continue
                if name.endswith("." + zone):
                    names.add(name)
    return names


def main() -> int:
    problems: list[str] = []
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    zone = inventory["lab"]["zone"]
    origin, zone_records = parse_zone(ZONE_FILE)

    if origin != zone:
        problems.append(f"zone origin {origin!r} does not match inventory zone {zone!r}")

    inventory_records = {
        (record["name"].lower(), record["type"].upper(), str(record["value"]))
        for record in inventory["records"]
    }
    missing = sorted(inventory_records - zone_records)
    extra = sorted(record for record in zone_records - inventory_records if record[1] in RECORD_TYPES)
    if missing:
        problems.append(f"inventory records missing from the zone: {missing}")
    if extra:
        problems.append(f"zone records missing from the inventory: {extra}")

    probe_hosts = [line.strip() for line in TARGETS.read_text(encoding="utf-8").splitlines() if line.strip()]
    inventory_probes = [probe["host"] for probe in inventory["probes"]]
    if probe_hosts != inventory_probes:
        problems.append(f"targets.txt {probe_hosts} does not match inventory probes {inventory_probes}")

    dnsx = json.loads(DNSX_EXPECTED.read_text(encoding="utf-8"))
    if dnsx.get("zone") != zone or dnsx.get("resolver") != inventory["lab"]["resolver"]:
        problems.append(
            f"dnsx fixture zone/resolver {dnsx.get('zone')!r}/{dnsx.get('resolver')!r} "
            f"does not match inventory {zone!r}/{inventory['lab']['resolver']!r}"
        )
    dnsx_probes = {probe["host"]: probe for probe in dnsx["probes"]}
    if sorted(dnsx_probes) != sorted(inventory_probes):
        problems.append(f"dnsx fixture hosts {sorted(dnsx_probes)} do not match inventory probes {sorted(inventory_probes)}")
    index = records_by_name(zone_records)
    for probe in inventory["probes"]:
        fixture = dnsx_probes.get(probe["host"])
        if fixture is None:
            continue
        if fixture["status_code"] != probe["status"]:
            problems.append(
                f"{probe['host']}: fixture status {fixture['status_code']!r}, inventory {probe['status']!r}"
            )
        if probe["status"] == "NOERROR":
            derived = expected_for(probe["host"], index)
            for kind in ("a", "aaaa", "cname"):
                if sorted(fixture.get(kind) or []) != derived[kind]:
                    problems.append(
                        f"{probe['host']} {kind}: fixture {sorted(fixture.get(kind) or [])} "
                        f"does not match zone {derived[kind]}"
                    )
        elif any(fixture.get(kind) for kind in ("a", "aaaa", "cname")):
            problems.append(f"{probe['host']}: {probe['status']} probe carries records")

    passive = inventory["passive"]
    derived_names = passive_names(zone, LAB / passive["fixture"])
    if derived_names != set(passive["names"]):
        problems.append(
            f"passive fixture yields {sorted(derived_names)}, inventory names {sorted(passive['names'])}"
        )
    subfinder = json.loads(SUBFINDER_EXPECTED.read_text(encoding="utf-8"))
    if subfinder.get("zone") != zone.rstrip(".") or subfinder.get("source") != passive["source"]:
        problems.append(f"subfinder fixture zone/source mismatch: {subfinder.get('zone')!r}/{subfinder.get('source')!r}")
    if sorted(subfinder["hosts"]) != sorted(passive["names"]):
        problems.append(f"subfinder fixture hosts {sorted(subfinder['hosts'])} do not match inventory passive names")

    images = parse_images()
    for key, env_name in ENV_NAMES.items():
        if key not in inventory["images"]:
            problems.append(f"inventory images has no {key!r}, but images.env pins {env_name}")
            continue
        want = inventory["images"][key]["ref"]
        if images.get(env_name) != want:
            problems.append(f"{env_name} is {images.get(env_name)!r}, inventory records {want!r}")

    problems.extend(check_services(inventory, index, images))
    problems.extend(check_naabu_fixture(inventory))

    if problems:
        print(f"lab inventory: FAIL ({len(problems)} problem(s))", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"lab inventory: PASS ({len(inventory_records)} records, {len(inventory_probes)} probes, "
        f"{len(passive['names'])} passive names, {len(ENV_NAMES)} image pins)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
