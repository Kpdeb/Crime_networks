"""Advanced graph analytics for NEXUS.

Adds network-level insights on top of the existing centrality/community logic:
- network density
- connected components
- clustering coefficient
- k-core membership
- articulation/bridge candidates
- shortest path between requested entities
- per-person composite network insight score

This module is deterministic and uses NetworkX only, so it remains compatible
with the current prototype while providing a clear upgrade path to Neo4j GDS.
"""

from __future__ import annotations

from typing import Any
import networkx as nx


def _undirected(graph: nx.MultiDiGraph) -> nx.Graph:
    """Collapse multi-edges/direction for structural network metrics."""
    return nx.Graph(graph)


def compute_network_summary(graph: nx.MultiDiGraph) -> dict[str, Any]:
    """Return network-wide structural metrics."""
    g = _undirected(graph)
    node_count = g.number_of_nodes()
    edge_count = g.number_of_edges()

    components = list(nx.connected_components(g)) if node_count else []
    component_sizes = sorted((len(c) for c in components), reverse=True)

    density = nx.density(g) if node_count > 1 else 0.0
    avg_clustering = nx.average_clustering(g) if node_count else 0.0

    return {
        "nodes": node_count,
        "edges": edge_count,
        "density": round(density, 4),
        "average_clustering": round(avg_clustering, 4),
        "connected_components": len(components),
        "largest_component_size": component_sizes[0] if component_sizes else 0,
        "component_sizes": component_sizes,
    }


def compute_k_core(graph: nx.MultiDiGraph) -> dict[str, int]:
    """Return each node's k-core number."""
    g = _undirected(graph)
    if not g:
        return {}
    return {node: int(core) for node, core in nx.core_number(g).items()}


def compute_articulation_points(graph: nx.MultiDiGraph) -> list[str]:
    """Find nodes whose removal would split the undirected network."""
    g = _undirected(graph)
    if g.number_of_nodes() < 3:
        return []
    return sorted(nx.articulation_points(g))


def compute_person_network_insights(graph: nx.MultiDiGraph, top_n: int = 10) -> list[dict[str, Any]]:
    """Combine existing centrality metrics with k-core and local clustering."""
    simple = nx.DiGraph(graph)
    undirected = _undirected(graph)

    if not simple:
        return []

    degree = nx.degree_centrality(simple)
    betweenness = nx.betweenness_centrality(simple)
    try:
        pagerank = nx.pagerank(simple)
    except Exception:
        pagerank = degree

    core = compute_k_core(graph)
    articulation = set(compute_articulation_points(graph))
    clustering = nx.clustering(undirected)

    persons = [n for n, d in simple.nodes(data=True) if d.get("type") == "Person"]
    max_core = max((core.get(n, 0) for n in persons), default=1) or 1

    rows: list[dict[str, Any]] = []
    for node in persons:
        network_score = (
            0.30 * degree.get(node, 0.0)
            + 0.30 * betweenness.get(node, 0.0)
            + 0.25 * pagerank.get(node, 0.0) * len(persons)
            + 0.10 * (core.get(node, 0) / max_core)
            + 0.05 * clustering.get(node, 0.0)
        )
        rows.append({
            "name": node,
            "degree_centrality": round(degree.get(node, 0.0), 4),
            "betweenness_centrality": round(betweenness.get(node, 0.0), 4),
            "pagerank": round(pagerank.get(node, 0.0), 4),
            "k_core": core.get(node, 0),
            "clustering": round(clustering.get(node, 0.0), 4),
            "articulation_candidate": node in articulation,
            "network_insight_score": round(network_score, 4),
        })

    rows.sort(key=lambda x: x["network_insight_score"], reverse=True)
    return rows[:top_n]


def shortest_path(graph: nx.MultiDiGraph, source: str, target: str) -> dict[str, Any]:
    """Return a shortest relationship path between two entities."""
    g = _undirected(graph)
    if source not in g or target not in g:
        return {"found": False, "path": [], "hops": None}

    try:
        path = nx.shortest_path(g, source=source, target=target)
    except nx.NetworkXNoPath:
        return {"found": False, "path": [], "hops": None}

    return {
        "found": True,
        "path": path,
        "hops": max(0, len(path) - 1),
    }
