# scripts/postprocess_enriched_techniques.py
"""
Post-process enriched techniques JSONL.

Ensures:
- data_component_ids is deduplicated
- log_source_names is deduplicated

NOTE: This script is now mostly redundant since enrich_techniques_with_data_components.py
already performs deduplication. It's kept for backward compatibility or if you need
to re-process an existing file.
"""

import json
import sys
from pathlib import Path

# Use relative paths from repo root
REPO_ROOT = Path(__file__).resolve().parents[1]
IN_PATH = REPO_ROOT / "data" / "processed" / "mitre" / "techniques_full_enriched.jsonl"
OUT_PATH = REPO_ROOT / "data" / "processed" / "mitre" / "techniques_full_enriched.jsonl"


def dedupe_preserve_order(items):
    """Deduplicate list while preserving order."""
    if not items:
        return []
    seen = set()
    out = []
    for x in items:
        if x is None:
            continue
        x_str = str(x).strip()
        if not x_str:
            continue
        if x_str in seen:
            continue
        seen.add(x_str)
        out.append(x_str)
    return out


def main():
    if not IN_PATH.exists():
        print(f"[error] Input file not found: {IN_PATH}")
        sys.exit(1)
    
    # Read all records FIRST (before opening output file)
    print(f"[postprocess] Reading from: {IN_PATH}")
    records = []
    with open(IN_PATH, "r", encoding="utf-8") as fin:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                t = json.loads(line)
                records.append(t)
            except json.JSONDecodeError as e:
                print(f"[warn] Skipping malformed line: {e}")
                continue
    
    if not records:
        print(f"[error] No valid records found in {IN_PATH}")
        print("[error] Aborting to prevent data loss.")
        sys.exit(1)
    
    print(f"[postprocess] Loaded {len(records)} techniques")
    
    # Process records
    total = 0
    with_dc = 0
    
    for t in records:
        total += 1
        
        dcs = t.get("data_components") or []
        if dcs:
            with_dc += 1
        
        # Dedupe data_component_ids
        dc_ids = t.get("data_component_ids") or []
        if not dc_ids and dcs:
            dc_ids = [dc.get("data_component_id") for dc in dcs if dc.get("data_component_id")]
        t["data_component_ids"] = dedupe_preserve_order(dc_ids)
        
        # Dedupe log_source_names
        ls_names = t.get("log_source_names") or []
        if not ls_names and dcs:
            for dc in dcs:
                for ls in (dc.get("log_sources") or []):
                    name = ls.get("name")
                    if name:
                        ls_names.append(name)
        t["log_source_names"] = dedupe_preserve_order(ls_names)
    
    # Write output (now safe since we have all data in memory)
    print(f"[postprocess] Writing to: {OUT_PATH}")
    with open(OUT_PATH, "w", encoding="utf-8") as fout:
        for t in records:
            fout.write(json.dumps(t, ensure_ascii=False) + "\n")
    
    print(f"[ok] Total techniques: {total}")
    print(f"[ok] Techniques with data components: {with_dc}")
    print(f"[ok] Wrote: {OUT_PATH}")


if __name__ == "__main__":
    main()