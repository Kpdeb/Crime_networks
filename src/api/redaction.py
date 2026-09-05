"""
Identity Redaction Module
===========================
The Women Safety Division handles cases where the complainant is often a
victim, not a suspect. This module lets the system mask complainant/victim
names across every output (dashboard, search, PDF reports) while keeping
full detail on accused individuals — protecting victim privacy without
losing any investigative capability against the actual network of suspects.
"""

import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def load_complainants() -> dict:
    path = DATA_DIR / "complainants.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _label_for(name: str, complainants: dict) -> str:
    idx = list(complainants.keys()).index(name) + 1
    return f"Complainant #{idx} [Identity Protected]"


def redact_name(name: str, redact: bool) -> str:
    """Return a masked label if this name belongs to a known complainant/victim
    and redaction is enabled; otherwise return the name unchanged."""
    if not redact:
        return name
    complainants = load_complainants()
    if name in complainants:
        return _label_for(name, complainants)
    return name


def redact_text(text: str, redact: bool) -> str:
    """Replace any complainant/victim name mentioned inside free text (e.g. an
    FIR excerpt) with a masked label."""
    if not redact:
        return text
    complainants = load_complainants()
    for name in complainants:
        label = _label_for(name, complainants)
        text = re.sub(re.escape(name), label, text)
    return text


def is_complainant(name: str) -> bool:
    return name in load_complainants()
