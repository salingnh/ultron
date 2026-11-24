"""M23 - graph projector, projection cursor and graph.* queries (owner: G1.4b).

Two entry points share this package:

* `python -m aegis.m23_graph run|rebuild|status` - the operator commands (`cli.py`);
* `aegis.m23_graph.queries` - the six read-only `graph.*` queries the MCP server (G1.2b) and the
  REST API (G1.4b) both use.

The projector is the only writer of Neo4j (`contracts/graph/model.md`): one consumer per generation,
checkpoint only after the graph commit, rebuild under a new generation.
"""

from __future__ import annotations

from aegis.m23_graph.projector import Projector, ProjectorBusy, ProjectorConfig

__all__ = ["Projector", "ProjectorBusy", "ProjectorConfig"]
