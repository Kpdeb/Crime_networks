"""Lightweight multilingual NLP support for Indian-language investigation text.

This module is intentionally dependency-light. It detects common Indian writing
scripts and provides language-aware relationship cue dictionaries. Entity
extraction continues to use the existing spaCy/regex pipeline; a future model
can be plugged in per language without changing the API contract.
"""

from __future__ import annotations

import re
from collections import Counter

LANGUAGE_NAMES = {
    "en": "English",
    "hi": "Hindi",
    "bn": "Bengali",
    "ta": "Tamil",
    "te": "Telugu",
    "mr": "Marathi",
    "unknown": "Unknown",
}

# Relationship cues. The labels are kept consistent with the existing graph
# so multilingual text lands in the same NetworkX/Soroban/API data model.
RELATIONSHIP_CUES = {
    "en": {
        "call": "CALLED", "called": "CALLED", "contact": "CONTACTED",
        "contacted": "CONTACTED", "transfer": "TRANSFERRED_MONEY",
        "transaction": "TRANSFERRED_MONEY", "met": "MET_WITH",
        "meeting": "MET_WITH", "associate": "ASSOCIATED_WITH",
        "financier": "FINANCIAL_LINK", "coordinator": "COORDINATES_WITH",
    },
    "hi": {
        "कॉल": "CALLED", "फोन": "CALLED", "बात": "CONTACTED",
        "संपर्क": "CONTACTED", "मिली": "MET_WITH", "मिला": "MET_WITH",
        "मुलाकात": "MET_WITH", "लेनदेन": "TRANSFERRED_MONEY",
        "पैसे भेजे": "TRANSFERRED_MONEY", "संबंध": "ASSOCIATED_WITH",
    },
    "bn": {
        "ফোন": "CALLED", "কল": "CALLED", "যোগাযোগ": "CONTACTED",
        "সাক্ষাৎ": "MET_WITH", "মিটিং": "MET_WITH", "লেনদেন": "TRANSFERRED_MONEY",
        "সম্পর্ক": "ASSOCIATED_WITH",
    },
    "ta": {
        "அழைத்தார்": "CALLED", "தொடர்பு": "CONTACTED", "சந்தித்தார்": "MET_WITH",
        "சந்திப்பு": "MET_WITH", "பரிவர்த்தனை": "TRANSFERRED_MONEY", "உறவு": "ASSOCIATED_WITH",
    },
    "te": {
        "ఫోన్": "CALLED", "సంప్రదింపు": "CONTACTED", "కలిశారు": "MET_WITH",
        "సమావేశం": "MET_WITH", "లావాదేవీ": "TRANSFERRED_MONEY", "సంబంధం": "ASSOCIATED_WITH",
    },
    "mr": {
        "फोन": "CALLED", "संपर्क": "CONTACTED", "भेटला": "MET_WITH",
        "भेट": "MET_WITH", "व्यवहार": "TRANSFERRED_MONEY", "संबंध": "ASSOCIATED_WITH",
    },
}

SCRIPT_RANGES = {
    "hi": ((0x0900, 0x097F),),  # Devanagari: Hindi/Marathi are approximated together
    "bn": ((0x0980, 0x09FF),),
    "ta": ((0x0B80, 0x0BFF),),
    "te": ((0x0C00, 0x0C7F),),
}


def _count_script_chars(text: str, ranges: tuple[tuple[int, int], ...]) -> int:
    return sum(1 for ch in text if any(lo <= ord(ch) <= hi for lo, hi in ranges))


def detect_language(text: str) -> str:
    """Detect the dominant supported script; otherwise return English/unknown."""
    scores = {
        "hi": _count_script_chars(text, SCRIPT_RANGES["hi"]),
        "bn": _count_script_chars(text, SCRIPT_RANGES["bn"]),
        "ta": _count_script_chars(text, SCRIPT_RANGES["ta"]),
        "te": _count_script_chars(text, SCRIPT_RANGES["te"]),
    }
    best, score = max(scores.items(), key=lambda kv: kv[1])
    if score >= 2:
        # Devanagari covers Hindi and Marathi. Prefer Marathi when common
        # Marathi-only markers are present; otherwise default to Hindi.
        if best == "hi" and re.search(r"\b(आहे|आणि|मध्ये|करून|होते)\b", text):
            return "mr"
        return best
    if re.search(r"[A-Za-z]", text):
        return "en"
    return "unknown"


def language_profile(text: str) -> dict:
    lang = detect_language(text)
    return {
        "language": lang,
        "language_name": LANGUAGE_NAMES.get(lang, lang),
        "script": "Devanagari" if lang in {"hi", "mr"} else LANGUAGE_NAMES.get(lang, "Unknown"),
        "supported": lang in LANGUAGE_NAMES and lang != "unknown",
    }


def relationship_cues_for(text: str) -> dict[str, str]:
    lang = detect_language(text)
    cues = dict(RELATIONSHIP_CUES["en"])
    cues.update(RELATIONSHIP_CUES.get(lang, {}))
    return cues
