"""Grounded AI Investigator for the criminal-network-analysis prototype.

This module intentionally uses deterministic, source-backed analysis rather than
an unrestricted language model. It converts a small set of natural-language
investigator questions into graph queries and returns the supporting signals
used for the answer.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import networkx as nx

from graph.build_graph import (
    compute_key_influencers,
    compute_risk_scores,
)
from graph.advanced_analytics import shortest_path
from nlp.entity_extractor import process_fir_file


PERSON_PATTERN = re.compile(r"[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}")
ENTITY_ID_PATTERN = re.compile(r"\b(?:P|A|V|L|ORG)-[A-Z0-9-]+\b", re.I)


def _all_people(G: nx.MultiDiGraph) -> List[str]:
    return [n for n, d in G.nodes(data=True) if d.get("type") == "Person"]


def _find_entity_name(question: str, candidates: List[str]) -> str | None:
    q = question.lower()
    for name in candidates:
        if name.lower() in q:
            return name
    return None


def _extract_person_candidates(question: str, candidates: List[str]) -> List[str]:
    found=[]
    q=question.lower()
    for name in candidates:
        if name.lower() in q and name not in found:
            found.append(name)
    if len(found) >= 2:
        return found[:2]
    return found


def _supporting_evidence(name: str, fir_reports: list[dict[str, Any]]) -> list[dict[str, str]]:
    sources=[]
    for report in fir_reports:
        people=report.get("entities", {}).get("persons", [])
        locations=report.get("entities", {}).get("locations", [])
        if name in people or name in locations:
            rels=report.get("relationships", [])
            rel_text=rels[0].get("evidence", "") if rels else "Entity appears in report."
            sources.append({
                "source_type":"FIR",
                "evidence":rel_text,
            })
    return sources[:5]


def answer_question(
    question: str,
    G: nx.MultiDiGraph,
    fir_reports: list[dict[str, Any]],
    risk_scores: list[dict[str, Any]],
    top_n: int = 5,
) -> Dict[str, Any]:
    q = question.strip()
    ql = q.lower()
    people = _all_people(G)

    if not q:
        return {"intent":"help","answer":"Ask about key connectors, connections between entities, risk indicators, or why an entity was highlighted.","sources":[]}

    # 1) Key connectors / influencers
    if any(word in ql for word in ["key connector", "key connectors", "influencer", "important person", "bridge"]):
        influencers = compute_key_influencers(G, top_n=top_n)
        items=[]
        for item in influencers:
            name=item.get("name")
            items.append({
                "entity": name,
                "signals": {
                    "degree": item.get("degree"),
                    "betweenness": item.get("betweenness"),
                    "pagerank": item.get("pagerank"),
                },
                "interpretation":"High network position / bridge-candidate signal; review source evidence before action.",
            })
        answer = "Top network connectors are ranked using degree, betweenness and PageRank. These are analytical priority signals, not findings of guilt."
        return {"intent":"key_connectors","answer":answer,"results":items,"sources":["NetworkX centrality analysis"]}

    # 2) Why an entity was highlighted / risk explanation
    if any(word in ql for word in ["why", "flagged", "highlighted", "risk", "priority"]):
        name = _find_entity_name(q, people)
        if not name:
            return {"intent":"entity_explanation","answer":"Please include a known person name, for example: Why was Rajesh Verma highlighted?","sources":[]}
        score = next((s for s in risk_scores if s.get("name") == name), None)
        if not score:
            return {"intent":"entity_explanation","answer":f"No risk record was found for {name}.","sources":[]}
        evidence=_supporting_evidence(name, fir_reports)
        return {
            "intent":"entity_explanation",
            "answer":f"{name} has an investigation-priority score of {score.get('score')}. The score combines network position and available alert/FIR signals.",
            "entity":name,
            "risk":score,
            "supporting_evidence":evidence,
            "note":"This is an analytical indicator and must be reviewed by an investigator.",
        }

    # 3) Connection / shortest path
    if any(word in ql for word in ["connected", "connection", "path", "how is"]):
        names=_extract_person_candidates(q, people)
        if len(names)<2:
            return {"intent":"connection","answer":"Please include two known person names, for example: How is Rajesh Verma connected to Anil Ghosh?","sources":[]}
        result=shortest_path(G, names[0], names[1])
        return {
            "intent":"connection",
            "answer":f"Shortest relationship path between {names[0]} and {names[1]} has {result.get('length')} hop(s).",
            "source":names[0],
            "target":names[1],
            "path":result.get("path", []),
            "relationships":result.get("relationships", []),
        }

    # 4) Entity network
    if any(word in ql for word in ["network", "connections", "2-hop", "two-hop"]):
        name=_find_entity_name(q, people)
        if not name:
            return {"intent":"entity_network","answer":"Please include a known person name, for example: Show Rajesh Verma's network.","sources":[]}
        neighbors=list(G.neighbors(name))
        second=set()
        for n in neighbors:
            second.update(G.neighbors(n))
        second.discard(name)
        return {
            "intent":"entity_network",
            "answer":f"{name} has {len(neighbors)} direct connection(s) and {len(second)} unique 2-hop reachable entity/entities in the current graph.",
            "entity":name,
            "direct_connections":neighbors,
            "two_hop_entities":sorted(second),
        }

    return {
        "intent":"help",
        "answer":"Try: 'Who are the key connectors?', 'Why was Rajesh Verma highlighted?', 'How is Rajesh Verma connected to Anil Ghosh?', or 'Show Rajesh Verma network.'",
        "sources":[],
    }
