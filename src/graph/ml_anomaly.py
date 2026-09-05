"""ML-based anomaly detection for transaction records.
Uses Isolation Forest to score unusual transaction behavior while preserving
NEXUS's existing rule-based detector as a complementary signal.
"""
from __future__ import annotations

from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def _prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    work = df.copy()
    work["amount"] = pd.to_numeric(work["amount"], errors="coerce").fillna(0.0)
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")
    work["hour"] = work["timestamp"].dt.hour.fillna(0)
    work["minute"] = work["timestamp"].dt.minute.fillna(0)
    work["weekday"] = work["timestamp"].dt.weekday.fillna(0)

    # Frequency/count features provide context beyond amount alone.
    sender_counts = work["sender_name"].value_counts()
    receiver_counts = work["receiver_name"].value_counts()
    work["sender_frequency"] = work["sender_name"].map(sender_counts).fillna(1)
    work["receiver_frequency"] = work["receiver_name"].map(receiver_counts).fillna(1)

    return work


def detect_ml_transaction_anomalies(csv_path: Path, contamination: float = 0.15) -> list[dict]:
    """Return ML anomaly scores for each transaction.

    The output is an anomaly indicator, not a finding of guilt.
    """
    df = pd.read_csv(csv_path)
    required = {"txn_id", "sender_name", "receiver_name", "amount", "timestamp", "mode"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing transaction columns: {sorted(missing)}")

    if len(df) < 4:
        return []

    work = _prepare_features(df)
    feature_cols = ["amount", "hour", "minute", "weekday", "sender_frequency", "receiver_frequency"]
    X = work[feature_cols].astype(float)
    X = StandardScaler().fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=min(max(contamination, 0.01), 0.49),
        random_state=42,
    )
    labels = model.fit_predict(X)
    raw_scores = -model.score_samples(X)

    low, high = float(raw_scores.min()), float(raw_scores.max())
    if high - low < 1e-9:
        scaled = [50.0] * len(raw_scores)
    else:
        scaled = [round(100 * (s - low) / (high - low), 1) for s in raw_scores]

    results = []
    for idx, row in work.iterrows():
        score = scaled[idx]
        results.append({
            "transaction_id": str(row["txn_id"]),
            "sender": str(row["sender_name"]),
            "receiver": str(row["receiver_name"]),
            "amount": float(row["amount"]),
            "timestamp": str(row["timestamp"]),
            "mode": str(row["mode"]),
            "anomaly_score": score,
            "is_anomaly": bool(labels[idx] == -1),
            "method": "IsolationForest",
        })

    return sorted(results, key=lambda x: x["anomaly_score"], reverse=True)
