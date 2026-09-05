"""
Visualization Module
Generates:
  1. A static PNG network graph (matplotlib) — for direct PPT embedding
  2. An interactive HTML graph (pyvis) — for live demo during presentation
"""

import json
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
from pyvis.network import Network

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
OUT_DIR = PROJECT_ROOT / "outputs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

COLOR_MAP = {
    "Person": "#e74c3c",
    "Location": "#3498db",
    "Vehicle": "#f39c12",
    "Unknown": "#95a5a6",
}


def load_graph(json_path: Path) -> nx.DiGraph:
    with open(json_path) as f:
        data = json.load(f)

    G = nx.DiGraph()
    for node in data["nodes"]:
        G.add_node(node["id"], type=node["type"])
    for edge in data["edges"]:
        G.add_edge(edge["source"], edge["target"], relation=edge["relation"])
    return G


def draw_static_graph(G: nx.DiGraph, out_file: Path):
    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, k=0.9, seed=42)

    node_colors = [COLOR_MAP.get(G.nodes[n].get("type", "Unknown"), "#95a5a6") for n in G.nodes]
    node_sizes = [800 + 400 * G.degree(n) for n in G.nodes]

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9)
    nx.draw_networkx_labels(G, pos, font_size=9, font_weight="bold")
    nx.draw_networkx_edges(G, pos, alpha=0.4, arrows=True, arrowsize=12,
                            connectionstyle="arc3,rad=0.1")

    edge_labels = {(u, v): d["relation"] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)

    # Legend
    legend_handles = [
        plt.Line2D([0], [0], marker='o', color='w', label=k,
                    markerfacecolor=v, markersize=12)
        for k, v in COLOR_MAP.items() if k != "Unknown"
    ]
    plt.legend(handles=legend_handles, loc="upper left")

    plt.title("Criminal Network Analysis — Entity Relationship Graph", fontsize=14, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_file, dpi=200)
    plt.close()


def draw_interactive_graph(G: nx.DiGraph, out_file: Path):
    net = Network(height="750px", width="100%", directed=True, bgcolor="#111111", font_color="white")
    for n, data in G.nodes(data=True):
        color = COLOR_MAP.get(data.get("type", "Unknown"), "#95a5a6")
        size = 15 + 5 * G.degree(n)
        net.add_node(n, label=n, color=color, size=size, title=data.get("type", ""))
    for u, v, data in G.edges(data=True):
        net.add_edge(u, v, title=data.get("relation", ""), label=data.get("relation", ""))

    net.repulsion(node_distance=180, spring_length=200)
    net.write_html(str(out_file), open_browser=False, notebook=False)


if __name__ == "__main__":
    G = load_graph(DATA_DIR / "graph_for_viz.json")

    static_path = OUT_DIR / "criminal_network_graph.png"
    draw_static_graph(G, static_path)
    print(f"✅ Static graph saved: {static_path}")

    interactive_path = OUT_DIR / "criminal_network_interactive.html"
    draw_interactive_graph(G, interactive_path)
    print(f"✅ Interactive graph saved: {interactive_path}")
