"""
Tamper-Proof Evidence Audit Log
================================
Every time a new entity or relationship is discovered by the NLP/graph
pipeline, we log it here as a block in a hash-chain — exactly like a
blockchain ledger. Each block stores the hash of the previous block,
so any attempt to alter a past record breaks the chain and is instantly
detectable. This gives investigators (and courts) a verifiable
chain-of-custody for how evidence was derived.

This module is a lightweight local simulation of the concept for the
prototype/demo. The production version of this system would write
these same log entries to a Soroban smart contract on the Stellar
network (see contracts/audit_log/src/lib.rs in this repo) so the
audit trail is verifiable on a public, decentralized ledger — not
just trusted to whoever controls this database.
"""

import hashlib
import json
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_FILE = PROJECT_ROOT / "data" / "audit_chain.json"


def _hash_block(block: dict) -> str:
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()


def load_chain() -> list:
    if LOG_FILE.exists():
        with open(LOG_FILE) as f:
            return json.load(f)
    return []


def save_chain(chain: list):
    with open(LOG_FILE, "w") as f:
        json.dump(chain, f, indent=2)


def add_evidence_block(event_type: str, details: dict) -> dict:
    """
    Append a new tamper-evident block to the audit chain.
    event_type examples: 'ENTITY_EXTRACTED', 'RELATIONSHIP_INFERRED', 'ALERT_RAISED'
    """
    chain = load_chain()
    previous_hash = chain[-1]["block_hash"] if chain else "0" * 64

    block = {
        "index": len(chain),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "details": details,
        "previous_hash": previous_hash,
    }
    block["block_hash"] = _hash_block(block)

    chain.append(block)
    save_chain(chain)
    return block


def verify_chain_integrity() -> dict:
    """
    Walk the entire chain and confirm every block's stored hash matches
    a freshly recomputed hash, and that previous_hash links are unbroken.
    Returns a report investigators/courts could use to prove evidence
    has not been tampered with since it was logged.
    """
    chain = load_chain()
    if not chain:
        return {"valid": True, "blocks_checked": 0, "message": "Chain is empty."}

    for i, block in enumerate(chain):
        recomputed = _hash_block({k: v for k, v in block.items() if k != "block_hash"})
        if recomputed != block["block_hash"]:
            return {"valid": False, "broken_at_block": i, "message": "Block hash mismatch — evidence may have been altered."}
        if i > 0 and block["previous_hash"] != chain[i - 1]["block_hash"]:
            return {"valid": False, "broken_at_block": i, "message": "Chain link broken — a block may be missing or reordered."}

    return {"valid": True, "blocks_checked": len(chain), "message": "All blocks verified. Evidence chain is intact."}


def log_pipeline_run(entities_result: list, influencers: list, alerts: list):
    """Convenience function: log a full pipeline run's key outputs as audit blocks."""
    for report in entities_result:
        if report["entities"]["persons"]:
            add_evidence_block("ENTITY_EXTRACTED", {
                "persons": report["entities"]["persons"],
                "source_snippet": report["raw_text"],
            })
    for inf in influencers:
        add_evidence_block("KEY_INFLUENCER_IDENTIFIED", inf)
    for alert in alerts:
        add_evidence_block("ALERT_RAISED", alert)


if __name__ == "__main__":
    import sys
    sys.path.append(str(PROJECT_ROOT / "src"))
    from nlp.entity_extractor import process_fir_file
    from graph.build_graph import (
        build_graph_from_fir_data, build_graph_from_cdr, build_graph_from_transactions,
        compute_key_influencers, detect_suspicious_transaction_pattern,
    )
    import networkx as nx

    DATA_DIR = PROJECT_ROOT / "data"

    entities_result = process_fir_file(str(DATA_DIR / "sample_fir_reports.txt"))

    G = nx.MultiDiGraph()
    build_graph_from_fir_data(G, DATA_DIR / "extracted_entities.json")
    build_graph_from_cdr(G, DATA_DIR / "sample_cdr.csv")
    build_graph_from_transactions(G, DATA_DIR / "sample_transactions.csv")
    influencers = compute_key_influencers(G)
    alerts = detect_suspicious_transaction_pattern(DATA_DIR / "sample_transactions.csv")

    print("Logging pipeline outputs to tamper-proof audit chain...")
    log_pipeline_run(entities_result, influencers, alerts)

    report = verify_chain_integrity()
    print(f"\n✅ Chain verification: {report}")

    print(f"\nTotal blocks in chain: {len(load_chain())}")
    print("Sample block:")
    print(json.dumps(load_chain()[0], indent=2))
