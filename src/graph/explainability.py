"""Explainable investigation-priority summaries built from existing NEXUS signals."""

from pathlib import Path
from .build_graph import compute_risk_scores, compute_key_influencers, detect_suspicious_transaction_pattern
from .advanced_analytics import compute_person_network_insights


def explain_person(graph, person_name: str, fir_json_path: Path, txn_csv_path: Path) -> dict:
    scores = compute_risk_scores(graph, fir_json_path, txn_csv_path)
    target = next((x for x in scores if x["name"] == person_name), None)
    if not target:
        return {"error": f"No person named '{person_name}' found in risk analysis."}

    influencers = compute_key_influencers(graph, top_n=100)
    rank = next((i for i, x in enumerate(influencers, 1) if x["name"] == person_name), None)
    insight = next((x for x in compute_person_network_insights(graph, top_n=100) if x["name"] == person_name), None)

    reasons = []
    breakdown = target.get("breakdown", {})
    if breakdown.get("centrality", 0) > 0:
        reasons.append({
            "signal": "Network centrality",
            "value": breakdown["centrality"],
            "explanation": "The entity occupies a relatively connected/central position in this case graph.",
        })
    if target.get("bridges_networks"):
        reasons.append({
            "signal": "Cross-network bridge",
            "value": breakdown.get("cross_network_bridge", 0),
            "explanation": "The entity has links that touch more than one detected community, making it a bridge candidate.",
        })
    if target.get("alert_count", 0):
        reasons.append({
            "signal": "Suspicious-activity alerts",
            "value": target["alert_count"],
            "explanation": "The entity is involved in one or more rule-based transaction anomaly flags.",
        })
    if target.get("fir_count", 0):
        reasons.append({
            "signal": "FIR mentions",
            "value": target["fir_count"],
            "explanation": "The entity appears in distinct FIR reports within the demo corpus.",
        })

    # Trace direct suspicious transaction flags involving this person.
    tx_flags = [
        flag for flag in detect_suspicious_transaction_pattern(txn_csv_path)
        if flag.get("sender") == person_name or flag.get("receiver") == person_name
    ]

    source_refs = []
    for flag in tx_flags[:10]:
        source_refs.append({
            "source_type": "TRANSACTION_PATTERN",
            "description": flag["reasoning"],
            "confidence": flag.get("confidence"),
        })

    if target.get("fir_count", 0):
        source_refs.append({
            "source_type": "FIR",
            "description": f"Referenced in {target['fir_count']} distinct FIR report(s) in the demo dataset.",
        })

    next_action = (
        "Review the supporting source records and relationship path before taking investigative action."
    )
    if target.get("bridges_networks") and insight:
        next_action = "Review the bridge connections and the source records that created those cross-community links."
    elif tx_flags:
        next_action = "Review the flagged transaction sequence and underlying transaction records."

    return {
        "entity": person_name,
        "investigation_priority": target["risk_score"],
        "risk_level": target["risk_level"],
        "confidence_note": "This is an investigation-support indicator, not a finding of guilt.",
        "why_highlighted": reasons,
        "centrality_rank": rank,
        "network_context": insight or {},
        "supporting_sources": source_refs,
        "recommended_review": next_action,
    }
