"""Worker process for the spike: orchestrator queue + agent queue in one process.

The tests start and SIGKILL this process to prove the restart path.
"""

from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from . import config
from .activities import AGENT_ACTIVITIES, ORCHESTRATOR_ACTIVITIES
from .session_workflow import SessionWorkflow
from .workflows import CampaignWorkflow


async def main() -> None:
    client = await Client.connect(config.TEMPORAL_ADDRESS, namespace=config.TEMPORAL_NAMESPACE)
    workers = [
        Worker(
            client,
            task_queue=config.ORCHESTRATOR_QUEUE,
            workflows=[CampaignWorkflow],
            activities=ORCHESTRATOR_ACTIVITIES,
        ),
        Worker(
            client,
            task_queue=config.AGENT_QUEUE,
            workflows=[SessionWorkflow],  # variant B lives on the agent queue
            activities=AGENT_ACTIVITIES,
        ),
    ]
    print(
        f"WORKER_READY address={config.TEMPORAL_ADDRESS} "
        f"queues={config.ORCHESTRATOR_QUEUE},{config.AGENT_QUEUE}",
        flush=True,
    )
    await asyncio.gather(*(w.run() for w in workers))


if __name__ == "__main__":
    asyncio.run(main())
