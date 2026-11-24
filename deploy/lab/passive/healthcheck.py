#!/usr/bin/env python3
"""Health check for the lab passive-source stub, run inside its container.

It verifies the whole path a Subfinder run uses: the lab CA, the `crt.sh` certificate, the
exact authorized query, and a JSON body that still carries the fixture's names.
"""

import json
import ssl
import sys
import urllib.request

ZONE = "lab.aegis.test"
URL = f"https://crt.sh/?q=%25.{ZONE}&output=json"


def main() -> int:
    context = ssl.create_default_context(cafile="/lab-tls/ca.crt")
    try:
        with urllib.request.urlopen(URL, context=context, timeout=3) as response:
            records = json.loads(response.read())
    except Exception as error:  # noqa: BLE001 - any failure means not healthy
        print(f"passive stub: {error}", file=sys.stderr)
        return 1
    names = set()
    for record in records:
        for field in ("common_name", "name_value"):
            for name in str(record.get(field, "")).splitlines():
                if name.endswith("." + ZONE) or name == ZONE:
                    names.add(name)
    if not names:
        print("passive stub: fixture has no name in the lab zone", file=sys.stderr)
        return 1
    print(f"passive stub: {len(names)} lab names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
