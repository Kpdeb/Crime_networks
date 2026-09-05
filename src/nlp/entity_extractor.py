"""
Entity Extraction Module
Extracts persons, locations, organizations (via spaCy NER)
and phone numbers, vehicle numbers, amounts (via regex patterns)
from unstructured crime report text.
"""

import re
import json
import spacy
from pathlib import Path
from .multilingual import language_profile, relationship_cues_for

nlp = spacy.load("en_core_web_sm")

# Project root is two levels up from this file (src/nlp/entity_extractor.py -> project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# --- Regex patterns for domain-specific entities spaCy won't catch out of the box ---
PHONE_PATTERN = re.compile(r"\b[6-9]\d{9}\b")
VEHICLE_PATTERN = re.compile(r"\b[A-Z]{2}-\d{2}-[A-Z]{2}-\d{4}\b")
AMOUNT_PATTERN = re.compile(r"Rs\.?\s?[\d,]+")
DATE_PATTERN = re.compile(r"\b\d{2}/\d{2}/\d{4}\b")

# Known locations gazetteer — used to correct spaCy misclassifications
# (spaCy sometimes tags Indian place names as PERSON since it wasn't trained on them)
KNOWN_LOCATIONS = {
    "kolkata", "howrah", "sealdah", "salt lake", "barasat", "park street",
    "kolkata,", "salt lake, kolkata", "lajpat nagar", "paharganj", "delhi",
}


def _clean_name(name: str) -> str:
    """Strip possessives and stray punctuation from an extracted name."""
    name = name.replace("'s", "").replace("’s", "")
    return name.strip(" ,.")


def extract_entities(text: str) -> dict:
    """Run spaCy NER + regex extraction on a single block of text, with
    gazetteer-based correction for common Indian place-name misclassification."""
    doc = nlp(text)

    raw_persons = {_clean_name(ent.text) for ent in doc.ents if ent.label_ == "PERSON"}
    raw_locations = {_clean_name(ent.text) for ent in doc.ents if ent.label_ in ("GPE", "LOC")}

    # Reclassify anything spaCy called a PERSON but that matches our known-location list
    persons = {p for p in raw_persons if p.lower() not in KNOWN_LOCATIONS}
    misclassified_locations = {p for p in raw_persons if p.lower() in KNOWN_LOCATIONS}
    locations = raw_locations | misclassified_locations

    # Drop empty strings / single-character noise, and anything that's actually
    # a vehicle number, phone number, date, or report ID misclassified as a person
    FIR_ID_PATTERN = re.compile(r"^FIR-\d+$", re.IGNORECASE)
    persons = {p for p in persons if len(p) > 2
               and not VEHICLE_PATTERN.search(p)
               and not PHONE_PATTERN.search(p)
               and not DATE_PATTERN.search(p)
               and not FIR_ID_PATTERN.match(p)}
    locations = {l for l in locations if len(l) > 2 and not DATE_PATTERN.search(l)}

    # Drop single-word person names that are just the trailing surname of a
    # fuller two-word name already captured elsewhere in this document
    # (spaCy sometimes splits "Deepak Malhotra" into a separate "Malhotra" mention)
    multi_word = [p for p in persons if " " in p]
    def is_truncated_surname(name):
        if " " in name:
            return False
        return any(name == full.split()[-1] for full in multi_word)
    persons = {p for p in persons if not is_truncated_surname(p)}

    entities = {
        "persons": sorted(persons),
        "locations": sorted(locations),
        "organizations": sorted(set(ent.text for ent in doc.ents if ent.label_ == "ORG")),
        "phone_numbers": sorted(set(PHONE_PATTERN.findall(text))),
        "vehicle_numbers": sorted(set(VEHICLE_PATTERN.findall(text))),
        "amounts": sorted(set(AMOUNT_PATTERN.findall(text))),
        "dates": sorted(set(DATE_PATTERN.findall(text))),
    }
    return entities


def extract_relationships(text: str, entities: dict) -> list:
    """
    Very lightweight rule-based relationship extraction.
    Looks for co-occurrence of two persons in the same sentence,
    and tags the relationship type using keyword cues.
    This is a starting point — round-1 prototype level, not production NLP.
    """
    relationships = []
    doc = nlp(text)

    keyword_map = relationship_cues_for(text)

    for sent in doc.sents:
        sent_text = sent.text
        persons_in_sent = [p for p in entities["persons"] if p in sent_text]
        persons_in_sent = list(dict.fromkeys(persons_in_sent))  # dedupe, preserve order
        if len(persons_in_sent) >= 2:
            rel_type = "ASSOCIATED_WITH"  # default
            sent_lower = sent_text.lower()
            for kw, label in sorted(keyword_map.items(), key=lambda kv: len(kv[0]), reverse=True):
                haystack = sent_lower if re.fullmatch(r"[\x00-\x7F]*", kw) else sent_text
                needle = kw.lower() if haystack is sent_lower else kw
                if needle in haystack:
                    rel_type = label
                    break
            for i in range(len(persons_in_sent)):
                for j in range(i + 1, len(persons_in_sent)):
                    relationships.append({
                        "source": persons_in_sent[i],
                        "target": persons_in_sent[j],
                        "type": rel_type,
                        "evidence": sent_text.strip()
                    })
    return relationships


def process_fir_file(filepath: str) -> list:
    """Process a text file containing multiple FIR reports separated by blank lines."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    reports = [r.strip() for r in content.split("\n\n") if r.strip()]
    results = []

    for report in reports:
        entities = extract_entities(report)
        relationships = extract_relationships(report, entities)
        results.append({
            "raw_text": report[:80] + "...",
            "language": language_profile(report),
            "entities": entities,
            "relationships": relationships
        })

    # Second pass: resolve truncated single-word surnames against the FULL
    # multi-word names seen anywhere across all reports (not just within the
    # same report) — spaCy occasionally drops the first name when a name
    # appears in a parenthetical aside, e.g. "(Deepak Malhotra)".
    all_multi_word = {p for r in results for p in r["entities"]["persons"] if " " in p}

    def resolve(name):
        if " " in name:
            return name
        matches = [full for full in all_multi_word if full.split()[-1] == name]
        return matches[0] if matches else name

    for r in results:
        resolved_persons = {resolve(p) for p in r["entities"]["persons"]}
        r["entities"]["persons"] = sorted(resolved_persons)
        for rel in r["relationships"]:
            rel["source"] = resolve(rel["source"])
            rel["target"] = resolve(rel["target"])

    return results


if __name__ == "__main__":
    output = process_fir_file(str(DATA_DIR / "sample_fir_reports.txt"))

    print(json.dumps(output, indent=2))

    with open(DATA_DIR / "extracted_entities.json", "w") as f:
        json.dump(output, f, indent=2)

    print("\n✅ Extraction complete. Saved to data/extracted_entities.json")
