"""
Optional Neo4j persistence layer for the criminal-network graph.

This module is deliberately optional: the existing NetworkX pipeline keeps
working when Neo4j is not installed or the Neo4j server is unavailable.
Enable it by setting NEO4J_URI, NEO4J_USER and NEO4J_PASSWORD.
"""

from __future__ import annotations

import os
from typing import Any

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - optional dependency
    GraphDatabase = None


class Neo4jStore:
    """Small adapter that mirrors a NetworkX graph into Neo4j."""

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "nexus_dev_password")
        self.driver = None

    def _ensure_driver(self) -> None:
        if GraphDatabase is None:
            raise RuntimeError(
                "Neo4j driver is not installed. Run: pip install neo4j"
            )
        if self.driver is None:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
            )

    def close(self) -> None:
        if self.driver is not None:
            self.driver.close()
            self.driver = None

    def verify_connection(self) -> dict[str, Any]:
        """Return a safe connection-status payload."""
        self._ensure_driver()
        with self.driver.session() as session:
            result = session.run("RETURN 1 AS ok, datetime() AS server_time").single()
            return {
                "connected": bool(result and result["ok"] == 1),
                "uri": self.uri,
                "server_time": str(result["server_time"]) if result else None,
            }

    def ensure_constraints(self) -> None:
        self._ensure_driver()
        statements = [
            "CREATE CONSTRAINT nexus_entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE",
        ]
        with self.driver.session() as session:
            for statement in statements:
                session.run(statement).consume()

    def sync_networkx_graph(self, graph) -> dict[str, int]:
        """Replace the demo Neo4j graph with the current NetworkX graph."""
        self._ensure_driver()
        self.ensure_constraints()

        nodes = [
            {"id": str(node), "type": data.get("type", "Unknown")}
            for node, data in graph.nodes(data=True)
        ]
        edges = [
            {
                "source": str(source),
                "target": str(target),
                "relation": str(data.get("relation", "RELATED_TO")),
                "source_type": str(data.get("source_type", "UNKNOWN")),
            }
            for source, target, data in graph.edges(data=True)
        ]

        with self.driver.session() as session:
            # Demo/prototype behavior: keep Neo4j synchronized with the
            # current source-of-truth graph rather than creating duplicates.
            session.run("MATCH (n:Entity) DETACH DELETE n").consume()

            session.run(
                """
                UNWIND $nodes AS node
                MERGE (n:Entity {id: node.id})
                SET n.type = node.type
                """,
                nodes=nodes,
            ).consume()

            session.run(
                """
                UNWIND $edges AS edge
                MATCH (source:Entity {id: edge.source})
                MATCH (target:Entity {id: edge.target})
                MERGE (source)-[r:RELATED_TO {relation: edge.relation, source_type: edge.source_type}]->(target)
                """,
                edges=edges,
            ).consume()

        return {"nodes": len(nodes), "edges": len(edges)}

    def fetch_network(self) -> dict[str, list[dict[str, Any]]]:
        """Return Neo4j graph data in the same shape as the frontend graph API."""
        self._ensure_driver()
        with self.driver.session() as session:
            node_rows = session.run(
                "MATCH (n:Entity) RETURN n.id AS id, n.type AS type ORDER BY n.id"
            )
            edge_rows = session.run(
                """
                MATCH (a:Entity)-[r:RELATED_TO]->(b:Entity)
                RETURN a.id AS source, b.id AS target,
                       r.relation AS relation, r.source_type AS source_type
                ORDER BY source, target
                """
            )
            nodes = [dict(row) for row in node_rows]
            edges = [dict(row) for row in edge_rows]
        return {"nodes": nodes, "edges": edges}
