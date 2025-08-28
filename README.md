# CWE Search Tool

A simple Python tool to search **CWE (Common Weakness Enumeration)** from the [MITRE CWE Dictionary](https://cwe.mitre.org).  
Supports both fuzzy and strict (deterministic) search, and can export results to **TXT, CSV, JSON**.  

## Installation
```bash
git clone https://github.com/<username>/<repo>.git
cd <repo>
pip install -r requirements.txt
```

## Usage
Fuzzy search (default):
```bash
python cwe_search.py "broken access control"
```

Strict search (exact phrase, without fuzzy):
```bash
python cwe_search.py "sql injection" --strict phrase --filter-only
```

Export results to files:
```bash
python cwe_search.py "cross-site scripting" --strict phrase --filter-only \
  --out-txt results.txt --out-csv results.csv --out-json results.json
```

## Example Output
```
Hasil untuk: 'cross-site scripting', matched: filter-only
 1. CWE-692: Incomplete Denylist to Cross-Site Scripting - https://cwe.mitre.org/data/definitions/692.html
```

## License
MIT License © 2025  
