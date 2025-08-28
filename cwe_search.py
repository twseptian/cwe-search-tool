#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CWE Search Tool (English version)

- Downloads and parses the MITRE CWE XML dictionary (cached locally).
- Builds a lightweight index with: id, name, url, alt_terms, description snippet, and ChildOf relations.
- Supports fuzzy search and deterministic strict filtering (any/all/phrase/regex).
- Can include related (children) CWE items with a configurable policy.
- Exports results to TXT, CSV, JSON.
- Prints stdout in the requested format:
  Results for: 'query', matched: <mode>
    1. CWE-xxx: Name - URL
"""

import os
import re
import io
import sys
import json
import csv
import zipfile
import difflib
import argparse
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import requests
except ImportError:
    print("Missing dependency 'requests'. Please install: pip install requests")
    sys.exit(1)

# -----------------------------------------------------------------------------
# Paths & Constants
# -----------------------------------------------------------------------------

CACHE_DIR = Path.home() / ".cache" / "cwe-search"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Update if MITRE releases a new version; this one works at time of writing.
DEFAULT_CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_v4.17.xml.zip"
CWE_ZIP_PATH = CACHE_DIR / "cwec.xml.zip"
CWE_XML_PATH = CACHE_DIR / "cwec.xml"
CWE_JSON_CACHE = CACHE_DIR / "cwe_index.json"

# Will be filled with {id: record} after building/loading cache.
_IDMAP = {}

# -----------------------------------------------------------------------------
# Download & Parse
# -----------------------------------------------------------------------------

def download_cwe_xml(source_url: str = DEFAULT_CWE_ZIP_URL, force: bool = False) -> None:
    """Download the CWE XML ZIP from MITRE and extract the main XML into cache."""
    if CWE_XML_PATH.exists() and not force:
        return
    print(f"[i] Downloading CWE XML from: {source_url}")
    r = requests.get(source_url, timeout=60)
    r.raise_for_status()
    CWE_ZIP_PATH.write_bytes(r.content)

    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        xml_candidates = [n for n in zf.namelist() if n.lower().endswith(".xml")]
        if not xml_candidates:
            raise RuntimeError("CWE ZIP file does not contain any XML.")
        # Choose the largest XML file (usually the dictionary)
        xml_name = max(xml_candidates, key=lambda n: zf.getinfo(n).file_size)
        with zf.open(xml_name) as xf:
            CWE_XML_PATH.write_bytes(xf.read())
    print(f"[i] XML saved to: {CWE_XML_PATH}")

def _all_text(elem) -> str:
    """Collect all text from an XML element (including children), trimmed and joined."""
    if elem is None:
        return ""
    return " ".join(t.strip() for t in elem.itertext() if t and t.strip())

def build_index(force: bool = False) -> None:
    """Parse the CWE XML into a JSON cache and in-memory id map."""
    global _IDMAP

    if CWE_JSON_CACHE.exists() and not force:
        try:
            data = json.loads(CWE_JSON_CACHE.read_text(encoding="utf-8"))
            _IDMAP = {d["id"]: d for d in data}
            return
        except Exception:
            pass

    if not CWE_XML_PATH.exists():
        download_cwe_xml()

    print("[i] Parsing CWE XML ...")
    tree = ET.parse(str(CWE_XML_PATH))
    root = tree.getroot()

    items = {}
    parent_edges = []  # (child_id, parent_id) for Nature=ChildOf

    for w in root.iter():
        if not w.tag.endswith("Weakness"):
            continue

        wid = w.attrib.get("ID")
        name = w.attrib.get("Name")
        if not (wid and name):
            continue

        url = f"https://cwe.mitre.org/data/definitions/{wid}.html"
        status = w.attrib.get("Status", "")
        abstraction = w.attrib.get("Abstraction", "")
        structure = w.attrib.get("Structure", "")

        # Alternate Terms
        alt_terms = []
        for at in w.findall(".//{*}Alternate_Terms/{*}Alternate_Term"):
            term = at.attrib.get("Term") or _all_text(at)
            if term:
                alt_terms.append(term.strip())

        # Description + Extended Description (snippet)
        desc = _all_text(w.find(".//{*}Description")).strip()
        extd = _all_text(w.find(".//{*}Extended_Description")).strip()
        desc_snippet = (desc + " " + extd).strip()
        if len(desc_snippet) > 1200:
            desc_snippet = desc_snippet[:1200] + " …"

        # Related Weaknesses → ChildOf
        for rw in w.findall(".//{*}Related_Weaknesses/{*}Related_Weakness"):
            nature = rw.attrib.get("Nature", "")
            pid = rw.attrib.get("CWE_ID")
            if pid and "ChildOf" in nature:
                parent_edges.append((wid, pid))

        items[wid] = {
            "id": wid,
            "name": name,
            "url": url,
            "status": status,
            "abstraction": abstraction,
            "structure": structure,
            "alt_terms": alt_terms,
            "desc": desc_snippet,
            "children": [],  # to be filled below
        }

    # Build parent → children map
    for child, parent in parent_edges:
        if parent in items and child in items:
            items[parent]["children"].append(child)

    data = list(items.values())
    CWE_JSON_CACHE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    _IDMAP = {d["id"]: d for d in data}
    print(f"[i] CWE index saved to: {CWE_JSON_CACHE} (total {len(data)} entries)")

# -----------------------------------------------------------------------------
# Normalization & Scoring
# -----------------------------------------------------------------------------

def normalize(s: str) -> str:
    if s is None:
        return ""
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9\s\-_/&]+", " ", s)
    s = re.sub(r"\s+", " ", s)
    return s

def tokens(s: str):
    return set(normalize(s).split())

def jaccard(a, b) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b) or 1
    return inter / union

def partial_contains_score(q: str, t: str) -> float:
    """0..1 score: direct substring (1.0) or longest-common-substring ratio vs query length."""
    qn = normalize(q)
    tn = normalize(t)
    if not qn or not tn:
        return 0.0
    if qn in tn:
        return 1.0
    sm = difflib.SequenceMatcher(None, qn, tn)
    match = sm.find_longest_match(0, len(qn), 0, len(tn))
    return match.size / len(qn) if qn else 0.0

def score_record(query: str, rec: dict, fields=("name","alt","desc")):
    """Weighted score across name/alt/desc + which fields matched (for debugging)."""
    q_tokens = tokens(query)
    matched_fields = []

    # Name
    name = rec["name"]
    name_tokens = tokens(name)
    s_name = max(jaccard(q_tokens, name_tokens),
                 difflib.SequenceMatcher(None, normalize(query), normalize(name)).ratio())
    if s_name > 0.0:
        matched_fields.append("name")

    # Alternate terms
    s_alt = 0.0
    if rec.get("alt_terms"):
        for term in rec["alt_terms"]:
            s_alt = max(s_alt, jaccard(q_tokens, tokens(term)))
            s_alt = max(s_alt, partial_contains_score(query, term))
        if s_alt > 0.0:
            matched_fields.append("alt")

    # Description snippet
    s_desc = 0.0
    if rec.get("desc"):
        s_desc = partial_contains_score(query, rec["desc"])
        if s_desc > 0.0:
            matched_fields.append("desc")

    # Weights
    w_name = 0.6 if "name" in fields else 0.0
    w_alt  = 0.3 if "alt"  in fields else 0.0
    w_desc = 0.1 if "desc" in fields else 0.0

    score = w_name*s_name + w_alt*s_alt + w_desc*s_desc
    if q_tokens and q_tokens.issubset(name_tokens):
        score += 0.1

    return min(1.0, score), matched_fields

def aggregate_text(rec, fields=("name","alt","desc")) -> str:
    """Concatenate text from selected fields for strict filtering checks."""
    parts = []
    if "name" in fields: parts.append(rec["name"])
    if "alt" in fields: parts.append(" | ".join(rec.get("alt_terms", [])))
    if "desc" in fields: parts.append(rec.get("desc", ""))
    return "\n".join([p for p in parts if p])

# -----------------------------------------------------------------------------
# Deterministic Strict Filter
# -----------------------------------------------------------------------------

def strict_match_ok(query, rec, fields, mode="all", regex=None, exclude=None, case_sensitive=False) -> bool:
    text = aggregate_text(rec, fields)
    t = text if case_sensitive else text.lower()
    q = query if case_sensitive else query.lower()

    # Exclusion
    if exclude:
        ex_list = [e.strip() for e in exclude.split(",") if e.strip()]
        for ex in ex_list:
            exq = ex if case_sensitive else ex.lower()
            if exq and exq in t:
                return False

    if mode == "phrase":
        return q in t

    if mode == "any":
        toks = [tok for tok in q.split() if tok]
        return any(tok in t for tok in toks)

    if mode == "all":
        toks = [tok for tok in q.split() if tok]
        return all(tok in t for tok in toks) if toks else False

    if mode == "regex":
        if not regex:
            return False
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(regex, text, flags) is not None
        except re.error:
            return False

    # No strict filter
    return True

# -----------------------------------------------------------------------------
# Search
# -----------------------------------------------------------------------------

def search_cwe(
    query: str,
    topk: int = 20,
    threshold: float = 0.25,
    fields=("name","alt","desc"),
    include_related: bool = False,
    related_policy: str = "filter",  # filter | inherit
    use_fuzzy: bool = True,
    strict_mode: str = None,         # any | all | phrase | regex | None
    regex: str = None,
    exclude: str = None,
    case_sensitive: bool = False,
):
    """Search CWE records with optional fuzzy scoring and strict filtering."""
    if not CWE_JSON_CACHE.exists():
        build_index()

    global _IDMAP
    if not _IDMAP:
        data = json.loads(CWE_JSON_CACHE.read_text(encoding="utf-8"))
        _IDMAP = {d["id"]: d for d in data}
    data = list(_IDMAP.values())

    # Fuzzy phase (optional)
    base_hits = []
    if use_fuzzy:
        qn = normalize(query)
        synonyms = {
            "broken access controll": "broken access control",
            "xss": "cross site scripting",
            "csrf": "cross site request forgery",
            "sqli": "sql injection",
            "rce": "remote code execution",
        }
        qn = synonyms.get(qn, qn)
        query_for_score = qn if qn else query

        for rec in data:
            s, matched_fields = score_record(query_for_score, rec, fields)
            if s >= threshold:
                base_hits.append({
                    "id": rec["id"],
                    "name": rec["name"],
                    "url": rec["url"],
                    "score": round(float(s), 3),
                    "matched_fields": matched_fields or ["fuzzy"],
                })
        base_hits.sort(key=lambda x: x["score"], reverse=True)
    else:
        # Filter-only: start from all records with a neutral score.
        for rec in data:
            base_hits.append({
                "id": rec["id"],
                "name": rec["name"],
                "url": rec["url"],
                "score": 1.0,
                "matched_fields": ["filter-only"],
            })

    # Strict deterministic filter (post-filter)
    if strict_mode:
        filtered = []
        seen = set()
        for h in base_hits:
            rec = _IDMAP[h["id"]]
            if strict_match_ok(query, rec, fields, mode=strict_mode,
                               regex=regex, exclude=exclude, case_sensitive=case_sensitive):
                if h["id"] not in seen:
                    filtered.append(h)
                    seen.add(h["id"])
        base_hits = filtered

    # Include related children
    if include_related and base_hits:
        seen = {h["id"] for h in base_hits}
        extras = []
        for h in base_hits:
            rec = _IDMAP[h["id"]]
            for cid in rec.get("children", []):
                if cid in seen:
                    continue
                child = _IDMAP.get(cid)
                if not child:
                    continue
                if related_policy == "filter" and strict_mode:
                    if not strict_match_ok(query, child, fields, mode=strict_mode,
                                           regex=regex, exclude=exclude, case_sensitive=case_sensitive):
                        continue
                extras.append({
                    "id": child["id"],
                    "name": child["name"],
                    "url": child["url"],
                    "score": max(0.0, round((h.get("score") or 1.0) * 0.9, 3)),
                    "matched_fields": ["related" if related_policy == "inherit" else "related+filtered"],
                })
                seen.add(cid)
        base_hits.extend(extras)
        base_hits.sort(key=lambda x: x["score"], reverse=True)

    return base_hits[:topk]

# -----------------------------------------------------------------------------
# Saving
# -----------------------------------------------------------------------------

def save_txt(results, path):
    with open(path, "w", encoding="utf-8") as f:
        for h in results:
            f.write(f"CWE-{h['id']}: {h['name']} (score={h['score']})\n{h['url']}\n")
            if h.get("matched_fields"):
                f.write(f"matched: {', '.join(h['matched_fields'])}\n")
            f.write("\n")

def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CWE-ID", "Name", "Score", "URL", "Matched Fields"])
        for h in results:
            writer.writerow([h["id"], h["name"], h["score"], h["url"], "|".join(h.get("matched_fields", []))])

def save_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Search CWE records from the MITRE CWE dictionary.")
    ap.add_argument("query", help="Keyword(s), e.g., 'sql injection' / 'broken access control'")
    ap.add_argument("--topk", type=int, default=20, help="Number of top results (default: 20)")
    ap.add_argument("--refresh", action="store_true", help="Force re-download & re-index")
    ap.add_argument("--source", default=DEFAULT_CWE_ZIP_URL, help=f"CWE ZIP URL (default: {DEFAULT_CWE_ZIP_URL})")

    # Fuzzy vs Strict
    ap.add_argument("--min-score", type=float, default=0.25, help="Fuzzy score threshold (default: 0.25)")
    ap.add_argument("--fields", default="name,alt,desc",
                    help="Comma-separated fields to search: name,alt,desc (default: name,alt,desc)")
    ap.add_argument("--filter-only", action="store_true",
                    help="Disable fuzzy; use strict filtering only (deterministic).")

    # Strict filter options
    ap.add_argument("--strict", choices=["any", "all", "phrase", "regex"],
                    help="Enable strict deterministic filter mode.")
    ap.add_argument("--regex", help="Regex pattern if --strict=regex (e.g., (?i)\\bsql\\s+injection\\b)")
    ap.add_argument("--exclude", help="Comma-separated negative keywords to exclude")
    ap.add_argument("--case-sensitive", action="store_true", help="Strict matching becomes case-sensitive")

    # Relations
    ap.add_argument("--include-related", action="store_true", help="Also include ChildOf descendants")
    ap.add_argument("--related-policy", choices=["filter", "inherit"], default="filter",
                    help="filter: child must pass strict; inherit: child follows parent (default: filter)")

    # Output files
    ap.add_argument("--out-txt", help="Save results to TXT")
    ap.add_argument("--out-csv", help="Save results to CSV")
    ap.add_argument("--out-json", help="Save results to JSON")

    args = ap.parse_args()

    # Ensure cache
    if args.refresh or (not CWE_XML_PATH.exists()) or (not CWE_JSON_CACHE.exists()):
        download_cwe_xml(source_url=args.source, force=True)
        build_index(force=True)
    else:
        build_index(force=False)

    fields = tuple([s.strip().lower() for s in args.fields.split(",") if s.strip()])

    hits = search_cwe(
        query=args.query,
        topk=args.topk,
        threshold=args.min_score,
        fields=fields,
        include_related=args.include_related,
        related_policy=args.related_policy,
        use_fuzzy=(not args.filter_only),
        strict_mode=args.strict,
        regex=args.regex,
        exclude=args.exclude,
        case_sensitive=args.case_sensitive,
    )

    if not hits:
        print("No results. Try adjusting --strict/--regex or disable --filter-only.")
        sys.exit(0)

    # ----- Custom stdout format (as requested) -----
    if args.filter_only:
        matched_label = "filter-only"
    elif args.strict:
        matched_label = args.strict
    else:
        matched_label = "fuzzy"

    print(f"Results for: {args.query!r}, matched: {matched_label}")
    for i, h in enumerate(hits, 1):
        print(f" {i}. CWE-{h['id']}: {h['name']} - {h['url']}")

    # Save optional files
    if args.out_txt:
        save_txt(hits, args.out_txt)
        print(f"[i] Saved TXT: {args.out_txt}")
    if args.out_csv:
        save_csv(hits, args.out_csv)
        print(f"[i] Saved CSV: {args.out_csv}")
    if args.out_json:
        save_json(hits, args.out_json)
        print(f"[i] Saved JSON: {args.out_json}")

if __name__ == "__main__":
    main()
