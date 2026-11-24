"""Fake scanner of the M06 tests: writes output to /out like a real tool would.

    python3 -m aegis_probe.tool --lines 3 [--proxy-url URL] [--sleep 60] [--exit-code 1]
                                [--oom]

`--proxy-url` fetches through the job's proxy and records the status, so the egress tests can
assert what the tool actually reached.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(os.environ.get("AEGIS_PROBE_OUT", "/out"))


def _fetch(url: str) -> dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - test probe
            return {"url": url, "status": response.status, "body": response.read(200).decode()}
    except urllib.error.HTTPError as error:
        return {"url": url, "status": error.code, "body": error.read(400).decode()}
    except OSError as error:
        return {"url": url, "status": None, "error": str(error)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lines", type=int, default=2)
    parser.add_argument("--proxy-url", action="append", default=[])
    parser.add_argument("--sleep", type=float, default=0)
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--oom", action="store_true")
    parser.add_argument("--targets-file", default="/in/targets.txt")
    args = parser.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    if args.oom:
        chunks = []
        while True:
            chunks.append(bytearray(8 * 1024 * 1024))
    targets: list[str] = []
    path = Path(args.targets_file)
    if path.exists():
        targets = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    (OUT / "result.jsonl").write_text(
        "".join(
            json.dumps({"host": f"h{index}.{targets[0] if targets else 'probe'}"}) + "\n"
            for index in range(args.lines)
        ),
        encoding="utf-8",
    )
    (OUT / "targets-seen.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")
    if args.proxy_url:
        fetches = [_fetch(url) for url in args.proxy_url]
        (OUT / "http.json").write_text(json.dumps(fetches), encoding="utf-8")
        print(json.dumps(fetches), flush=True)
    if args.sleep:
        # Sleep after writing: the timeout/cancel tests then have output to collect, which is the
        # case the contract cares about ("stop, collect what is left, then remove").
        time.sleep(args.sleep)
    return int(args.exit_code)


if __name__ == "__main__":
    sys.exit(main())
