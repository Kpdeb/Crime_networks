# AI-Powered Criminal Network Analysis System

**Problem Statement ID:** 26189
**Organization:** Ministry of Home Affairs — National Crime Records Bureau (NCRB), Women Safety Division
**Theme:** Blockchain & Cybersecurity

## Problem

Investigators work with fragmented, unstructured data — FIRs, Call Detail Records (CDRs), financial
transactions, surveillance reports, social media intel — spread across multiple systems. Manually
connecting the dots between suspects, locations, phones, and money flows is slow and error-prone.

## Solution

An AI pipeline that automatically:
1. **Extracts entities** (people, phone numbers, vehicles, locations, amounts) from raw FIR text using NLP (spaCy NER + domain-specific pattern matching)
2. **Builds a relationship graph** connecting entities across FIRs, CDRs, and financial records
3. **Identifies key influencers** in the network using graph centrality (PageRank, betweenness, degree)
4. **Detects criminal sub-groups/cells** using community detection (Louvain algorithm)
5. **Flags suspicious patterns** such as transaction structuring ("smurfing")
6. **Logs every finding to a tamper-proof audit chain** — so the chain of evidence can't be silently altered, and any tampering is instantly detectable

## Architecture

```
Raw Data (FIR text, CDR, Transactions)
        │
        ▼
┌───────────────────┐
│   NLP Layer        │  spaCy NER + regex → entities & relationships
│ (src/nlp/)          │
└─────────┬──────────┘
          ▼
┌───────────────────┐
│  Graph Layer        │  NetworkX → key influencers, communities, anomalies
│ (src/graph/)         │
└─────────┬──────────┘
          ▼
┌───────────────────┐        ┌──────────────────────────────┐
│  API Layer           │◄────►│  Tamper-Proof Audit Log         │
│ (src/api/) FastAPI    │      │ (src/blockchain/) + Soroban       │
└─────────┬──────────┘        │  smart contract (contracts/)      │
          ▼                    └──────────────────────────────┘
   Investigator Dashboard
   (graph visualization, alerts)
```

## Repository Structure

```
data/                     Sample FIR text, CDR, transaction records (dummy data for demo)
src/nlp/                  Entity extraction (spaCy NER + regex patterns)
src/graph/                Graph construction + analytics (NetworkX)
src/api/                  FastAPI backend exposing the pipeline as REST endpoints
src/blockchain/           Local tamper-proof audit chain (hash-chain simulation)
contracts/audit_log/      Soroban smart contract — on-chain version of the audit log,
                           for deployment to Stellar testnet
```

## Running the Prototype

```bash
pip install -r requirements.txt   # spacy, networkx, matplotlib, pyvis, fastapi, uvicorn, python-louvain
python -m spacy download en_core_web_sm

# Run NLP extraction
python src/nlp/entity_extractor.py

# Build graph + run analytics
python src/graph/build_graph.py

# Generate visualizations
python src/graph/visualize.py

# Run the tamper-proof audit log demo
python src/blockchain/audit_log.py

# Start the API server
uvicorn src.api.main:app --reload --port 8000
```

### API Endpoints

All endpoints below (except `/` and `/login`) require a valid access token —
log in first via `/login`, then send `Authorization: Bearer <token>` with
every request. The dashboard handles this automatically.

| Endpoint | Description |
|---|---|
| `POST /login` | Authenticate and receive a signed, expiring access token |
| `GET /entities` | Entities + relationships extracted from FIR text |
| `GET /graph` | Full network graph (nodes + edges) |
| `GET /influencers` | Top individuals ranked by centrality (key players) |
| `GET /communities` | Detected criminal sub-groups/cells |
| `GET /alerts` | Suspicious activity flags |
| `GET /audit-chain` | Tamper-proof evidence log |
| `GET /search?q=` | Search entities by partial name |
| `GET /entity/{name}` | Full case-file view for one entity |
| `GET /explain/{name}` | Explain why an entity is highlighted, with supporting signals and source references |
| `GET /report/{name}` | Download a court-ready PDF case dossier for one entity |
| `GET /report/{name}` | Download a court-ready PDF case report for one entity |

### Demo Login Credentials

| Username | Password | Role |
|---|---|---|
| `investigator` | `ncrb@2026` | investigator |
| `admin` | `admin@2026` | admin |

These are seeded in `data/users.json` (passwords stored as salted PBKDF2 hashes,
never in plaintext). In production, accounts would be provisioned by a system
administrator, not shipped as demo defaults.

## Why Blockchain?

Court proceedings require a verifiable **chain of custody** for evidence. If an AI system silently
flags someone as a "key influencer" or an "alert," investigators and courts need proof that this
finding — and the data behind it — hasn't been altered after the fact. Logging every extraction,
inference, and alert to an append-only, cryptographically-linked chain (with the on-chain Soroban
version providing a public, decentralized guarantee) gives that proof.

## Tech Stack

- **NLP:** spaCy (NER), regex pattern matching
- **Graph Analytics:** NetworkX, python-louvain
- **Backend:** FastAPI
- **Visualization:** Matplotlib (static), Pyvis (interactive)
- **Blockchain:** Local hash-chain (prototype) + Soroban/Stellar smart contract (production path)

## ML Anomaly Detection

Added an Isolation Forest-based transaction anomaly indicator. The existing rule-based detector remains in place, so the two signals can be compared rather than replacing one another. ML scores are investigation indicators, not findings of guilt.

## Status

This is a Round 1 prototype demonstrating the core pipeline end-to-end on sample data. Not yet
implemented: multilingual FIR support (Hindi/regional languages), OCR for scanned reports,
production-grade relation extraction (currently rule-based), and live Soroban testnet deployment.


## Explainable Investigation Signals

The `/explain/{name}` endpoint expands the existing priority/risk score into human-readable signals, centrality context, suspicious-activity evidence references, and a recommended review step. The result is explicitly framed as an investigation-support indicator, not a finding of guilt.


## Security upgrade
Added restricted CORS for local development, login rate limiting, role-based authorization helper, production secret guard, and `/security/status` for authorized investigators/admins. Demo mode remains enabled by default; set `NEXUS_DEMO_MODE=0` and `APP_SECRET_KEY` in production-like environments.

## Step 8 — Evidence Integrity + Blockchain Upgrade
- `POST /evidence/hash` calculates a SHA-256 hash for an uploaded evidence file and records the hash in the local tamper-evident audit chain.
- `POST /evidence/verify` recalculates a file hash and reports `VERIFIED` or `INTEGRITY_FAILURE`.
- `GET /blockchain/status` reports that the Soroban contract path is present while clearly showing that live on-chain deployment is still pending.
- Raw sensitive evidence is never written to the blockchain by this upgrade; only cryptographic hashes/metadata are intended for the future on-chain layer.


## Real-time Intelligence
A near-real-time demo feed is available through protected `GET /realtime/events` and `POST /realtime/events` endpoints. The browser polls every 5 seconds and refreshes the Live Intelligence Feed. This is a local/synthetic demonstration of the event pipeline, not a live government/telecom feed.

## Multilingual NLP upgrade
Added lightweight language detection for English, Hindi, Bengali, Tamil, Telugu and Marathi scripts, language-aware relationship cues, multilingual report metadata, and `POST /multilingual/analyze`. The current upgrade is a multilingual-ready routing layer; full language-specific transformer NER models remain a future model layer.
