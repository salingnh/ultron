"""Local API server with graph_driver attached for real API verification."""
import os
import sys
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from neo4j import GraphDatabase
from aegis.m26_api.main import build_registry
from aegis.m26_api.app import create_app, cors_origins_from_env
from aegis.m26_api.operator import OperatorTokens, TokenAuthenticator
from aegis.m26_api import jobs

REPO_ROOT = Path(__file__).resolve().parents[2]
TOKENS_FILE = REPO_ROOT / ".local/operators.json"
DSN = os.environ.get("AEGIS_PG_DSN", "postgresql://aegis:aegis-dev-pg@127.0.0.1:15432/aegis")
NEO4J_URI = os.environ.get("AEGIS_NEO4J_URI", "bolt://127.0.0.1:17687")
NEO4J_AUTH = ("neo4j", os.environ.get("AEGIS_NEO4J_PASSWORD", "aegis-dev-neo4j"))

driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
tokens = OperatorTokens.from_file(str(TOKENS_FILE))

cors_origins = cors_origins_from_env() or ["*"]

app = create_app(
    build_registry(),
    operator_authenticator=TokenAuthenticator(tokens),
    database_dsn=DSN,
    cors_origins=cors_origins,
    graph_driver=driver,
)

jobs.install_job_service(app, jobs.build_job_service(DSN))
