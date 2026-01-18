# scripts/enrich_techniques_with_data_components.py
"""
Enrich MITRE techniques with detection strategies and data components.

FIX Issue 4: Now outputs to canonical filename (no version suffix)
"""

import json
import re
import ast
import os
import pandas as pd
from collections import defaultdict
from typing import Any, List, Tuple, Dict

TECH_JSONL_IN = os.getenv(
    "TECH_JSONL_IN",
    "data/raw/mitre/techniques_full.jsonl",
)
MAP_CSV = os.getenv(
    "MAP_CSV",
    "data/processed/mitre/technique_data_components.csv",
)

# FIX Issue 4: Use canonical filename (no version suffix)
TECH_JSONL_OUT = os.getenv(
    "TECH_JSONL_OUT",
    "data/processed/mitre/techniques_full_enriched.jsonl",  # ← CANONICAL
)


def _strip_trailing_commas(s: str) -> str:
    return re.sub(r",(\s*[\]}])", r"\1", s)


def load_techniques_any_format(path: str) -> Tuple[List[dict], str]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    if not raw.strip():
        return [], "empty"

    # 1) Try full-file JSON
    try:
        obj = json.loads(raw)
        return _extract_techniques(obj), "full_json"
    except Exception:
        pass

    # 2) Try sanitized JSON (trailing commas)
    try:
        cleaned = _strip_trailing_commas(raw)
        obj = json.loads(cleaned)
        return _extract_techniques(obj), "full_json_sanitized_trailing_commas"
    except Exception:
        pass

    # 3) Try Python literal
    try:
        obj = ast.literal_eval(raw)
        return _extract_techniques(obj), "python_literal"
    except Exception:
        pass

    # 4) JSONL fallback
    techniques: List[dict] = []
    wrapped_count = 0
    bad_lines = 0

    with open(path, "r", encoding="utf-8") as f:
        for _, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                bad_lines += 1
                continue

            if isinstance(o, dict) and "techniques" in o and isinstance(o["techniques"], list):
                techniques.extend(o["techniques"])
                wrapped_count += 1
            elif isinstance(o, dict):
                techniques.append(o)

    if techniques:
        tag = "jsonl_wrapped" if wrapped_count else "jsonl_per_line"
        if bad_lines:
            tag += f"_with_{bad_lines}_bad_lines"
        return techniques, tag

    preview = raw[:300].replace("\n", "\\n")
    raise RuntimeError(
        "Could not parse techniques file as JSON, sanitized JSON, python literal, or JSONL.\n"
        f"Preview (first 300 chars): {preview}"
    )


def _extract_techniques(obj: Any) -> List[dict]:
    if isinstance(obj, dict) and "techniques" in obj and isinstance(obj["techniques"], list):
        return obj["techniques"]
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        return [obj]
    return []


def write_jsonl(path: str, items: List[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for obj in items:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def _norm_str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, float) and pd.isna(x):
        return ""
    return str(x).strip()


def build_detection_strategy_index(map_csv_path: str) -> Dict[str, List[dict]]:
    """
    Build detection strategy hierarchy from mapping CSV.
    
    Structure:
        technique_id -> [
            {
                detection_strategy_stix_id,
                detection_strategy_name,
                analytics: [
                    {
                        analytic_stix_id,
                        analytic_name,
                        log_source_references: [...]
                    }
                ]
            }
        ]
    """
    df = pd.read_csv(map_csv_path)

    required_cols = {
        "technique_id",
        "data_component_id",
        "data_component_stix_id",
        "log_source_name",
        "log_source_channel",
        "detection_strategy_stix_id",
        "detection_strategy_name",
        "analytic_stix_id",
        "analytic_name",
    }
    missing = required_cols - set(df.columns)
    if missing:
        raise RuntimeError(
            f"Mapping CSV missing columns: {sorted(missing)}\n"
            "Your build_technique_data_components.py must output detection_strategy_* and analytic_* columns."
        )

    has_rel = "relationship_stix_id" in df.columns

    agg = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    ds_names = {}
    an_names = {}

    for _, r in df.iterrows():
        tid = _norm_str(r.get("technique_id"))
        if not tid:
            continue

        ds_id = _norm_str(r.get("detection_strategy_stix_id"))
        ds_name = _norm_str(r.get("detection_strategy_name"))

        an_id = _norm_str(r.get("analytic_stix_id"))
        an_name = _norm_str(r.get("analytic_name"))

        dc_id = _norm_str(r.get("data_component_id"))
        dc_stix = _norm_str(r.get("data_component_stix_id"))
        ls_name = _norm_str(r.get("log_source_name"))
        ls_chan = _norm_str(r.get("log_source_channel"))

        if not dc_id:
            continue

        rel_id = _norm_str(r.get("relationship_stix_id")) if has_rel else ""

        if ds_id:
            ds_names[(tid, ds_id)] = ds_name
        if ds_id and an_id:
            an_names[(tid, ds_id, an_id)] = an_name

        key_tuple = (dc_id, dc_stix, ls_name, ls_chan, rel_id)
        agg[tid][ds_id][an_id].add(key_tuple)

    out: Dict[str, List[dict]] = {}

    for tid, ds_map in agg.items():
        ds_list: List[dict] = []
        for ds_id, an_map in ds_map.items():
            analytics: List[dict] = []
            for an_id, tuples in an_map.items():
                refs = []
                for (dc_id, dc_stix, ls_name, ls_chan, rel_id) in sorted(tuples):
                    ref = {
                        "data_component_id": dc_id,
                        "data_component_stix_id": dc_stix,
                        "log_source_name": ls_name,
                        "log_source_channel": ls_chan,
                    }
                    if rel_id:
                        ref["relationship_stix_id"] = rel_id
                    refs.append(ref)

                analytics.append({
                    "analytic_stix_id": an_id,
                    "analytic_name": an_names.get((tid, ds_id, an_id), ""),
                    "log_source_references": refs,
                })

            ds_list.append({
                "detection_strategy_stix_id": ds_id,
                "detection_strategy_name": ds_names.get((tid, ds_id), ""),
                "analytics": analytics,
            })

        out[tid] = ds_list

    return out


def build_flat_data_components_from_strategies(detection_strategies: List[dict]) -> List[dict]:
    """
    Extract flattened data components list from detection strategies.
    This provides backward compatibility and easier access to telemetry.
    """
    dc_map = defaultdict(lambda: {"data_component_id": None, "data_component_stix_id": None, "log_sources": set()})

    for ds in detection_strategies or []:
        for an in (ds.get("analytics") or []):
            for lr in (an.get("log_source_references") or []):
                dcid = _norm_str(lr.get("data_component_id"))
                dcstix = _norm_str(lr.get("data_component_stix_id"))
                ls_name = _norm_str(lr.get("log_source_name"))
                ls_chan = _norm_str(lr.get("log_source_channel"))

                if not dcid:
                    continue

                entry = dc_map[dcid]
                entry["data_component_id"] = dcid
                entry["data_component_stix_id"] = dcstix
                entry["log_sources"].add((ls_name, ls_chan))

    dcs = []
    for dcid, entry in sorted(dc_map.items()):
        log_sources = [{"name": n, "channel": c} for (n, c) in sorted(entry["log_sources"])]
        dcs.append({
            "data_component_id": entry["data_component_id"],
            "data_component_stix_id": entry["data_component_stix_id"],
            "log_sources": log_sources,
        })
    return dcs


def extract_technique_level_telemetry(detection_strategies: List[dict]) -> Tuple[List[str], List[str]]:
    """
    Extract technique-level telemetry lists for backward compatibility.
    Returns (data_component_ids, log_source_names).
    """
    dc_ids = set()
    ls_names = set()

    for ds in detection_strategies or []:
        for an in (ds.get("analytics") or []):
            for lr in (an.get("log_source_references") or []):
                dcid = _norm_str(lr.get("data_component_id"))
                ls_name = _norm_str(lr.get("log_source_name"))
                
                if dcid:
                    dc_ids.add(dcid)
                if ls_name:
                    ls_names.add(ls_name)

    return sorted(dc_ids), sorted(ls_names)


def main():
    print(f"[enrich] Input: {TECH_JSONL_IN}")
    print(f"[enrich] Mapping: {MAP_CSV}")
    print(f"[enrich] Output: {TECH_JSONL_OUT}")  # FIX Issue 4: Now canonical
    
    ds_index = build_detection_strategy_index(MAP_CSV)
    techniques, fmt = load_techniques_any_format(TECH_JSONL_IN)

    print(f"[enrich] Loaded techniques: {len(techniques)} (format={fmt})")
    print(f"[enrich] Technique IDs with DetectionStrategy mappings: {len(ds_index)}")

    enriched = 0
    missing_tid = 0

    for t in techniques:
        tid = t.get("technique_id")
        if not tid:
            missing_tid += 1
            continue

        detection_strategies = ds_index.get(tid, [])
        
        # Add detection strategies (new canonical field)
        t["detection_strategies"] = detection_strategies
        
        # Add flattened data_components for backward compatibility
        t["data_components"] = build_flat_data_components_from_strategies(detection_strategies)
        
        # Add technique-level telemetry lists for easier access
        dc_ids, ls_names = extract_technique_level_telemetry(detection_strategies)
        t["data_component_ids"] = dc_ids
        t["log_source_names"] = ls_names

        if detection_strategies:
            enriched += 1

    write_jsonl(TECH_JSONL_OUT, techniques)

    print(f"[enrich] ✓ Enriched techniques (detection_strategies): {enriched}/{len(techniques)}")
    if missing_tid:
        print(f"[enrich] ⚠ Techniques missing technique_id field: {missing_tid}")
    print(f"[enrich] ✓ Wrote: {TECH_JSONL_OUT}")
    
    # FIX Issue 4: Warn about old versioned files
    import glob
    versioned_files = glob.glob("data/processed/mitre/techniques_full_enriched_v*.jsonl")
    if versioned_files:
        print(f"\n[enrich] ⚠ WARNING: Found {len(versioned_files)} versioned files:")
        for vf in versioned_files:
            print(f"[enrich]   - {vf}")
        print(f"[enrich]   Consider running: python scripts/consolidate_versions.py")


if __name__ == "__main__":
    main()