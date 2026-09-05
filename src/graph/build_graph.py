"""
Graph Construction & Analytics Module
Builds a criminal network graph from:
  - NLP-extracted entities/relationships (FIR reports)
  - CDR (call records)
  - Financial transaction records
Then runs analytics: centrality (key influencers), community detection (sub-groups),
suspicious transaction pattern detection, and composite risk scoring.
"""

import json
import csv
import networkx as nx
from pathlib import Path

try:
    import community as community_louvain  # python-louvain package
except ImportError:
    community_louvain = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def build_graph_from_fir_data(graph: nx.MultiDiGraph, fir_json_path: Path):
    """Add nodes/edges extracted from FIR text (NLP output)."""
    with open(fir_json_path) as f:
        fir_data = json.load(f)

    for report in fir_data:
        # Clean up known NER noise (apostrophe-s, stray non-person tokens)
        persons = [p.replace("'s", "").strip() for p in report["entities"]["persons"]]
        for p in persons:
            graph.add_node(p, type="Person")

        for loc in report["entities"]["locations"]:
            graph.add_node(loc, type="Location")

        for veh in report["entities"]["vehicle_numbers"]:
            graph.add_node(veh, type="Vehicle")

        for rel in report["relationships"]:
            src = rel["source"].replace("'s", "").strip()
            tgt = rel["target"].replace("'s", "").strip()
            graph.add_edge(src, tgt, relation=rel["type"], source_type="FIR")


def build_graph_from_cdr(graph: nx.MultiDiGraph, cdr_csv_path: Path):
    """Add CALLED edges from Call Detail Records."""
    with open(cdr_csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            caller = row["caller_name"]
            receiver = row["receiver_name"]
            graph.add_node(caller, type="Person")
            graph.add_node(receiver, type="Person")
            graph.add_edge(caller, receiver, relation="CALLED",
                            source_type="CDR", duration=row["duration_sec"],
                            location=row["tower_location"])


def build_graph_from_transactions(graph: nx.MultiDiGraph, txn_csv_path: Path):
    """Add TRANSFERRED_MONEY edges from financial transaction records."""
    with open(txn_csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            sender = row["sender_name"]
            receiver = row["receiver_name"]
            graph.add_node(sender, type="Person")
            graph.add_node(receiver, type="Person")
            graph.add_edge(sender, receiver, relation="TRANSFERRED_MONEY",
                            source_type="Transaction", amount=row["amount"])


def compute_key_influencers(graph: nx.MultiDiGraph, top_n=5):
    """Rank individuals by centrality measures to find key influencers/kingpins."""
    simple_graph = nx.DiGraph(graph)  # collapse multi-edges for centrality calc

    degree_centrality = nx.degree_centrality(simple_graph)
    betweenness_centrality = nx.betweenness_centrality(simple_graph)
    try:
        pagerank = nx.pagerank(simple_graph)
    except Exception as e:
        print(f"[warning] PageRank calculation failed ({e}); falling back to degree centrality. "
              f"Install scipy (pip install scipy) for accurate PageRank scores.")
        pagerank = degree_centrality

    scores = []
    for node in simple_graph.nodes:
        if simple_graph.nodes[node].get("type") != "Person":
            continue
        scores.append({
            "name": node,
            "degree_centrality": round(degree_centrality.get(node, 0), 3),
            "betweenness_centrality": round(betweenness_centrality.get(node, 0), 3),
            "pagerank": round(pagerank.get(node, 0), 3),
        })

    scores.sort(key=lambda x: x["pagerank"], reverse=True)
    return scores[:top_n]


def detect_communities(graph: nx.MultiDiGraph):
    """Detect sub-groups/cells within the network using Louvain community detection."""
    undirected = nx.Graph(graph)
    if community_louvain is None:
        return {}
    partition = community_louvain.best_partition(undirected)

    groups = {}
    for node, comm_id in partition.items():
        groups.setdefault(comm_id, []).append(node)
    return groups


def detect_suspicious_transaction_pattern(txn_csv_path: Path):
    """
    Rule-based structuring detection:
    Flags 3+ transfers between the same sender-receiver pair, within a close
    amount range of each other, as a possible 'smurfing' pattern used to
    dodge reporting thresholds (amounts don't need to be identical --
    real structuring often varies amounts slightly to look less suspicious).
    """
    from collections import defaultdict
    pairs = defaultdict(list)

    with open(txn_csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = (row["sender_name"], row["receiver_name"])
            pairs[key].append((row["timestamp"], int(row["amount"])))

    flags = []
    for (sender, receiver), txns in pairs.items():
        if len(txns) < 3:
            continue
        amounts = [amt for _, amt in txns]
        # Flag if amounts are all within 5% of their average (near-identical repeated transfers)
        avg = sum(amounts) / len(amounts)
        if all(abs(a - avg) / avg <= 0.05 for a in amounts):
            # Confidence scales with repeat count and how tightly amounts cluster —
            # more repeats and tighter clustering both make the pattern less likely
            # to be coincidental.
            max_deviation = max(abs(a - avg) / avg for a in amounts)
            confidence = min(0.98, 0.55 + 0.08 * len(amounts) + (0.05 - max_deviation))
            flags.append({
                "sender": sender,
                "receiver": receiver,
                "amount": round(avg),
                "repeat_count": len(amounts),
                "flag": "Possible structuring / smurfing pattern",
                "confidence": round(confidence, 2),
                "reasoning": (
                    f"{len(amounts)} transfers from {sender} to {receiver}, each within "
                    f"{round(max_deviation * 100, 1)}% of the average amount (₹{round(avg):,}). "
                    f"Splitting a larger sum into multiple near-equal transfers is a well-known "
                    f"'structuring' technique used to stay under mandatory cash-transaction "
                    f"reporting thresholds (e.g. the ₹10 lakh threshold under India's PMLA rules)."
                ),
            })
    return flags


def count_fir_mentions(fir_json_path: Path):
    """Count how many distinct FIR reports mention each person (not total name occurrences)."""
    from collections import defaultdict
    counts = defaultdict(int)

    with open(fir_json_path) as f:
        fir_data = json.load(f)

    for report in fir_data:
        persons_in_report = {p.replace("'s", "").strip() for p in report["entities"]["persons"]}
        for p in persons_in_report:
            counts[p] += 1

    return dict(counts)


def compute_risk_scores(graph: nx.MultiDiGraph, fir_json_path: Path, txn_csv_path: Path):
    """
    Composite 0-100 risk score per person, combining four signals:
      - Network centrality (35%): how connected/important the person is in the graph
        (average of normalized PageRank and betweenness centrality)
      - Suspicious activity alerts (30%): involvement in flagged structuring/smurfing
        transactions (capped at 2 alerts for full weight)
      - Cross-network bridge (20%): whether the person's direct connections span more
        than one detected community (i.e. they link two otherwise-separate networks)
      - FIR mentions (15%): how many distinct FIR reports name the person (capped at 4
        for full weight)

    Returns a list of dicts sorted by risk_score descending, each with a breakdown
    of the four component scores and a High/Medium/Low level.
    """
    simple_graph = nx.DiGraph(graph)
    undirected = nx.Graph(graph)

    betweenness = nx.betweenness_centrality(simple_graph)
    try:
        pagerank = nx.pagerank(simple_graph)
    except Exception:
        pagerank = nx.degree_centrality(simple_graph)

    # Normalize centrality measures to 0-1 against the max observed among persons,
    # so scores are relative to this network rather than absolute (Louvain/PageRank
    # values are usually small fractions and not comparable across graphs).
    person_nodes = [n for n, d in simple_graph.nodes(data=True) if d.get("type") == "Person"]
    max_pagerank = max((pagerank.get(n, 0) for n in person_nodes), default=1) or 1
    max_betweenness = max((betweenness.get(n, 0) for n in person_nodes), default=1) or 1

    # Alerts: count how many suspicious-transaction flags involve each person
    alert_flags = detect_suspicious_transaction_pattern(txn_csv_path)
    alert_counts = {}
    for flag in alert_flags:
        alert_counts[flag["sender"]] = alert_counts.get(flag["sender"], 0) + 1
        alert_counts[flag["receiver"]] = alert_counts.get(flag["receiver"], 0) + 1

    # Cross-network bridge: does this person's neighborhood touch more than one community?
    communities = detect_communities(graph)
    node_to_community = {}
    for comm_id, members in communities.items():
        for m in members:
            node_to_community[m] = comm_id

    fir_counts = count_fir_mentions(fir_json_path)
    max_fir_count = max(fir_counts.values(), default=1) or 1

    results = []
    for node in person_nodes:
        # --- Centrality (35%) ---
        norm_pagerank = pagerank.get(node, 0) / max_pagerank
        norm_betweenness = betweenness.get(node, 0) / max_betweenness
        centrality_score = ((norm_pagerank + norm_betweenness) / 2) * 35

        # --- Alerts (30%), capped at 2 alerts for full weight ---
        alerts = alert_counts.get(node, 0)
        alert_score = min(alerts / 2, 1) * 30

        # --- Cross-network bridge (20%) ---
        own_community = node_to_community.get(node)
        neighbor_communities = {
            node_to_community.get(n) for n in undirected.neighbors(node)
            if node_to_community.get(n) is not None
        }
        neighbor_communities.discard(own_community)
        bridges_networks = len(neighbor_communities) > 0
        bridge_score = 20 if bridges_networks else 0

        # --- FIR mentions (15%), capped at 4 reports for full weight ---
        fir_count = fir_counts.get(node, 0)
        fir_score = min(fir_count / min(4, max_fir_count), 1) * 15

        total = round(centrality_score + alert_score + bridge_score + fir_score)
        total = min(total, 100)

        if total >= 60:
            level = "High"
        elif total >= 30:
            level = "Medium"
        else:
            level = "Low"

        results.append({
            "name": node,
            "risk_score": total,
            "risk_level": level,
            "breakdown": {
                "centrality": round(centrality_score, 1),
                "alerts": round(alert_score, 1),
                "cross_network_bridge": bridge_score,
                "fir_mentions": round(fir_score, 1),
            },
            "alert_count": alerts,
            "fir_count": fir_count,
            "bridges_networks": bridges_networks,
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def export_for_visualization(graph: nx.MultiDiGraph, out_path: Path):
    """Export graph as JSON (nodes+edges) for frontend visualization (Cytoscape.js/D3)."""
    nodes = [{"id": n, "type": data.get("type", "Unknown")} for n, data in graph.nodes(data=True)]
    edges = [{"source": u, "target": v, "relation": data.get("relation", ""),
              "source_type": data.get("source_type", "")} for u, v, data in graph.edges(data=True)]
    with open(out_path, "w") as f:
        json.dump({"nodes": nodes, "edges": edges}, f, indent=2)


def export_risk_scores(scores: list, out_path: Path):
    """Export computed risk scores as JSON for the API/frontend to consume."""
    with open(out_path, "w") as f:
        json.dump(scores, f, indent=2)


if __name__ == "__main__":
    G = nx.MultiDiGraph()

    build_graph_from_fir_data(G, DATA_DIR / "extracted_entities.json")
    build_graph_from_cdr(G, DATA_DIR / "sample_cdr.csv")
    build_graph_from_transactions(G, DATA_DIR / "sample_transactions.csv")

    print(f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges\n")

    print("=== TOP KEY INFLUENCERS (by PageRank) ===")
    influencers = compute_key_influencers(G)
    for i, person in enumerate(influencers, 1):
        print(f"{i}. {person['name']} — PageRank: {person['pagerank']}, "
              f"Betweenness: {person['betweenness_centrality']}, "
              f"Degree: {person['degree_centrality']}")

    print("\n=== DETECTED SUB-GROUPS (Community Detection) ===")
    communities = detect_communities(G)
    for comm_id, members in communities.items():
        print(f"Group {comm_id}: {members}")

    print("\n=== SUSPICIOUS TRANSACTION PATTERNS ===")
    flags = detect_suspicious_transaction_pattern(DATA_DIR / "sample_transactions.csv")
    for flag in flags:
        print(flag)

    print("\n=== RISK SCORES ===")
    risk_scores = compute_risk_scores(G, DATA_DIR / "extracted_entities.json",
                                       DATA_DIR / "sample_transactions.csv")
    for person in risk_scores:
        bridge_note = " [BRIDGES NETWORKS]" if person["bridges_networks"] else ""
        print(f"{person['name']}: {person['risk_score']}/100 ({person['risk_level']}){bridge_note}")

    export_for_visualization(G, DATA_DIR / "graph_for_viz.json")
    print(f"\n✅ Graph data exported to {DATA_DIR / 'graph_for_viz.json'}")

    export_risk_scores(risk_scores, DATA_DIR / "risk_scores.json")
    print(f"✅ Risk scores exported to {DATA_DIR / 'risk_scores.json'}")