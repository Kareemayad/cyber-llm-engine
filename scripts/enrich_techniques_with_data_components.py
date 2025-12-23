import json
import re
import ast
import pandas as pd
from collections import defaultdict
from typing import Any, List, Tuple

TECH_JSONL_IN = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/techniques_full.jsonl"
MAP_CSV = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/technique_data_components.csv"
TECH_JSONL_OUT = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/techniques_full_enriched.jsonl"


def _strip_trailing_commas(s: str) -> str:
    # Remove trailing commas before } or ]
    # e.g. {"a":1,} -> {"a":1} and [1,2,] -> [1,2]
    return re.sub(r",(\s*[\]}])", r"\1", s)


def load_techniques_any_format(path: str) -> Tuple[List[dict], str]:
    """
    Supports:
      A) Proper JSON: {"techniques":[...]} OR [...]
      B) Pretty-printed multi-line JSON (same as A but formatted)
      C) JSON-like with trailing commas (we try to sanitize)
      D) Python literal dict/list (single quotes) via ast.literal_eval
      E) Proper JSONL where each line is a technique dict
      F) JSONL where each line is {"techniques":[...]} (we flatten)

    Returns: (techniques_list, format_tag)
    """
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

    # 2) Try full-file JSON after removing trailing commas
    try:
        cleaned = _strip_trailing_commas(raw)
        obj = json.loads(cleaned)
        return _extract_techniques(obj), "full_json_sanitized_trailing_commas"
    except Exception:
        pass

    # 3) Try Python literal (handles single quotes etc.)
    try:
        obj = ast.literal_eval(raw)
        return _extract_techniques(obj), "python_literal"
    except Exception:
        pass

    # 4) Fall back to JSONL parsing (strict per line JSON)
    techniques: List[dict] = []
    wrapped_count = 0
    bad_lines = 0

    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
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
            else:
                # ignore non-dict JSON lines
                continue

    if techniques:
        tag = "jsonl_wrapped" if wrapped_count else "jsonl_per_line"
        if bad_lines:
            tag += f"_with_{bad_lines}_bad_lines"
        return techniques, tag

    # If nothing worked, raise with a helpful snippet
    preview = raw[:300].replace("\n", "\\n")
    raise RuntimeError(
        "Could not parse techniques file as JSON, sanitized JSON, python literal, or JSONL.\n"
        f"Preview (first 300 chars): {preview}"
    )


def _extract_techniques(obj: Any) -> List[dict]:
    # obj can be {"techniques":[...]} or a list of dicts or a single technique dict
    if isinstance(obj, dict) and "techniques" in obj and isinstance(obj["techniques"], list):
        return obj["techniques"]
    if isinstance(obj, list):
        # could be list of techniques
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        # single technique dict
        return [obj]
    return []


def write_jsonl(path: str, items: List[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for obj in items:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def build_dc_index(map_csv_path: str):
    """
    technique_id -> list of:
      {
        data_component_id,
        data_component_stix_id,
        log_sources: [{name, channel}, ...]
      }
    """
    df = pd.read_csv(map_csv_path)

    required_cols = {
        "technique_id",
        "data_component_id",
        "data_component_stix_id",
        "log_source_name",
        "log_source_channel",
    }
    missing = required_cols - set(df.columns)
    if missing:
        raise RuntimeError(f"Mapping CSV missing columns: {sorted(missing)}")

    agg = defaultdict(lambda: defaultdict(lambda: {
        "data_component_id": None,
        "data_component_stix_id": None,
        "log_sources": set(),  # (name, channel)
    }))

    for _, r in df.iterrows():
        tid = str(r["technique_id"]).strip()
        dcid = str(r["data_component_id"]).strip()
        dcstix = str(r["data_component_stix_id"]).strip()

        ls_name = "" if pd.isna(r["log_source_name"]) else str(r["log_source_name"]).strip()
        ls_chan = "" if pd.isna(r["log_source_channel"]) else str(r["log_source_channel"]).strip()

        entry = agg[tid][dcid]
        entry["data_component_id"] = dcid
        entry["data_component_stix_id"] = dcstix
        entry["log_sources"].add((ls_name, ls_chan))

    out = {}
    for tid, dc_map in agg.items():
        dc_list = []
        for _, entry in dc_map.items():
            log_sources = [{"name": n, "channel": c} for (n, c) in sorted(entry["log_sources"])]
            dc_list.append({
                "data_component_id": entry["data_component_id"],
                "data_component_stix_id": entry["data_component_stix_id"],
                "log_sources": log_sources,
            })
        out[tid] = dc_list

    return out


def main():
    dc_index = build_dc_index(MAP_CSV)
    techniques, fmt = load_techniques_any_format(TECH_JSONL_IN)

    print(f"[debug] Loaded techniques: {len(techniques)} (format={fmt})")
    print(f"[debug] Technique IDs with DC mappings: {len(dc_index)}")

    enriched = 0
    missing_tid = 0

    for t in techniques:
        tid = t.get("technique_id")
        if not tid:
            missing_tid += 1
            continue

        dcs = dc_index.get(tid, [])
        t["data_components"] = dcs  # always present (empty list if none)

        if dcs:
            enriched += 1

    write_jsonl(TECH_JSONL_OUT, techniques)

    print(f"[ok] Enriched techniques: {enriched}/{len(techniques)}")
    print(f"[warn] Techniques missing technique_id field: {missing_tid}")
    print(f"[ok] Wrote: {TECH_JSONL_OUT}")


if __name__ == "__main__":
    main()
