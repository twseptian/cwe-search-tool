# CWE Search Tool

*Just a lazy tool to search CWE codes and enjoy them locally on your computer.*  
It fetches the latest CWE dictionary from [MITRE](https://cwe.mitre.org) and lets you quickly search using fuzzy or strict filters.  
Results can be exported to **TXT, CSV, or JSON**.  

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

Strict search (exact phrase, no fuzzy):
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
Results for: 'cross-site scripting', matched: filter-only
 1. CWE-692: Incomplete Denylist to Cross-Site Scripting - https://cwe.mitre.org/data/definitions/692.html
```

## License
MIT License © 2025  
