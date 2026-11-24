"""M03 agent session (G1.2c): the LangGraph loop that proposes jobs through MCP.

One `run_agent_session` activity call is one campaign cycle (02-nen-tang §Phiên agent). The graph
runs **inside** the activity (G0.1 decision) with a PostgreSQL checkpointer keyed by the
`agent_session.session_id`, and its nodes are the loop the spec fixes:

    BuildContext -> Plan -> SelectTool -> Dispatch -> AwaitResult -> Analyze -> DecideNext

Boundaries this module keeps (and the tests prove):

* the only way to start a job is `tools/call` on the M05 MCP boundary (`mcp.py`); M03 never calls
  the M05 service, the control-plane REST API or a shell;
* the model never gets authority: `SelectTool` validates its tool call against the catalogue the
  server published for this session, and `DecideNext` enforces budget/step limits in code;
* tool output is data. It is schema-parsed into typed fields, and every text it contributes to the
  prompt is wrapped in `UNTRUSTED_TOOL_OUTPUT` (`prompt.py`);
* `agent_session` (M03's own table) is the session authority the MCP server checks: the row is
  created `RUNNING` before the first tool call and finished with the contract `session-result.v2`.

Entry points: `aegis.m03_agent.activities` (Temporal activity, registered by
`python -m aegis.m02_orchestrator.worker --session-module aegis.m03_agent.activities`) and
`aegis.m03_agent.session.run_session` (the same loop without Temporal).
"""

from __future__ import annotations

__all__: list[str] = []
