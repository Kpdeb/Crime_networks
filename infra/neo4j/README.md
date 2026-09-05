# Optional Neo4j Development Service

This service is an optional next-stage graph database for NEXUS.

Start it with Docker:

```powershell
docker compose -f infra/neo4j/docker-compose.yml up -d
```

Then set these environment variables for the backend:

```text
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=nexus_dev_password
```

The API exposes:

- `GET /neo4j/status`
- `POST /neo4j/sync`
- `GET /neo4j/graph`

The existing NetworkX pipeline remains the primary source for the current prototype; Neo4j is an optional persistence/query layer until the integration is enabled and tested.
