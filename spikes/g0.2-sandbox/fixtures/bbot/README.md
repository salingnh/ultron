# BBOT fixture provenance

`bbot-passive.ndjson` is a **synthetic** BBOT JSON dump, not a capture from a
live run:

* no lab target set is authorized yet (plan OD-1), and this spike must not
  scan third-party domains, so no BBOT scan was executed;
* the event shapes (`type`, `data`, `scope_description`, `resolved_hosts`,
  `module`, `timestamp`, `host`, `url`, `status_code`, `netname`, `cidr`) are
  the fields the mapping in `aegis_g02/bbot_map.py` consumes, checked against
  the pinned BBOT 3.0.2 image (pin table, `pins/pin-table.md`);
* all names are under the reserved `.example` TLD and all addresses are from
  the documentation range `192.0.2.0/24`, so nothing here points at a real
  host.

G1 must replace this with a capture from an authorized lab scan before the
BBOT adapter is called conformant.
