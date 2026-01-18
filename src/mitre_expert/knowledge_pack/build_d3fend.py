#src/mitre_expert/knowledge_pack/build_d3fend.py
"""
build_d3fend_normalized.py

Inputs:
  - d3fend.json (JSON-LD ontology)
  - d3fend-full-mappings.csv (inferred mappings)

Outputs:
  1) Normal JSON (single file) with:
     - meta
     - defenses_by_d3fend_id (one object per D3FEND technique)
     - optionally all_nodes_by_uri (full-fidelity index of every node, for debugging / completeness)

  2) JSONL (one defense object per line) suitable for RAG chunking / indexing.

Key idea:
- Ontology nodes are in @graph with @id like "d3f:CredentialHardening"
- CSV uses full URIs like "http://d3fend.mitre.org/ontologies/d3fend.owl#CredentialHardening"
- We normalize ontology node @id to full URIs using @context, then join on CSV.def_tech.

Example:
  python build_d3fend_normalized.py \
    --csv "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/d3fend-full-mappings.csv" \
    --jsonld "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/d3fend.json" \
    --out-json "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/d3fend_normalized_v1.json" \
    --out-jsonl "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/d3fend_defenses_v1.jsonl" \
    --include-all-nodes
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _safe_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _is_id_obj(v: Any) -> bool:
    return isinstance(v, dict) and "@id" in v and len(v.keys()) <= 3


def _extract_ids(v: Any) -> List[str]:
    """
    Extract @id strings from:
      - {"@id": "..."}
      - [{"@id": "..."}, ...]
      - {"@list": [{"@id": "..."} ...]} (rare, but exists in JSON-LD)
    Otherwise returns [].
    """
    if v is None:
        return []

    # JSON-LD list form
    if isinstance(v, dict) and "@list" in v and isinstance(v["@list"], list):
        out: List[str] = []
        for item in v["@list"]:
            if _is_id_obj(item):
                out.append(str(item["@id"]))
        return out

    if _is_id_obj(v):
        return [str(v["@id"])]

    if isinstance(v, list):
        out = []
        for item in v:
            if _is_id_obj(item):
                out.append(str(item["@id"]))
        return out

    return []


def _parse_prefixed_id(prefixed: str) -> Tuple[Optional[str], str]:
    """
    "d3f:CredentialHardening" -> ("d3f", "CredentialHardening")
    "_:N123" -> (None, "_:N123")
    "https://..." -> (None, "https://...")
    """
    if prefixed.startswith("_:"):
        return (None, prefixed)
    if "://" in prefixed:
        return (None, prefixed)
    if ":" in prefixed:
        pfx, local = prefixed.split(":", 1)
        return (pfx, local)
    return (None, prefixed)


def _expand_id_to_uri(node_id: str, context: Dict[str, Any]) -> str:
    """
    Expand a JSON-LD @id to a full URI if possible, using @context.
    - "d3f:Something" -> context["d3f"] + "Something"
    - already full URI -> returned as-is
    - blank node "_:X" -> returned as-is (not a URI)
    """
    if node_id.startswith("_:") or "://" in node_id:
        return node_id

    pfx, local = _parse_prefixed_id(node_id)
    if pfx and pfx in context and isinstance(context[pfx], str):
        base = context[pfx]
        return f"{base}{local}"
    return node_id


def _canonicalize_node(node: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a raw JSON-LD node into a more readable "normal JSON" record while preserving data.
    """
    node_id = str(node.get("@id", ""))
    full_uri = _expand_id_to_uri(node_id, context)

    types = node.get("@type", [])
    if isinstance(types, str):
        types = [types]
    elif not isinstance(types, list):
        types = [str(types)]

    # Common fields
    label = node.get("rdfs:label") or node.get("skos:prefLabel") or ""
    definition = node.get("d3f:definition") or ""

    # D3FEND id if present
    d3fend_id = node.get("d3f:d3fend-id")

    # Keep all original properties (minus @id/@type) as "raw_properties"
    raw_properties: Dict[str, Any] = {}
    for k, v in node.items():
        if k in ("@id", "@type"):
            continue
        raw_properties[k] = v

    # Extract relations (predicate -> list of target ids) for any predicate whose value is an @id link/list
    relations: Dict[str, List[Dict[str, str]]] = {}
    for pred, v in raw_properties.items():
        ids = _extract_ids(v)
        if not ids:
            continue
        relations[pred] = [{"id": i, "uri": _expand_id_to_uri(i, context)} for i in ids]

    return {
        "node_id": node_id,
        "uri": full_uri,
        "types": types,
        "name": label,
        "definition": definition,
        "d3fend_id": d3fend_id,
        "relations": relations,
        "raw_properties": raw_properties,  # full fidelity
    }


def _read_csv_rows(path: str) -> Iterable[Dict[str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Normalize None -> ""
            yield {k: (v if v is not None else "") for k, v in row.items()}


def _uri_suffix(uri: str) -> str:
    """
    Return the fragment or last path component so we can do fallback matching.
    e.g. "...#TokenBinding" -> "TokenBinding"
         ".../TokenBinding" -> "TokenBinding"
    """
    if not uri:
        return ""
    if "#" in uri:
        return uri.rsplit("#", 1)[-1]
    return uri.rstrip("/").rsplit("/", 1)[-1]


def build_outputs(
    jsonld_path: str,
    csv_path: str,
    include_all_nodes: bool = False,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = _load_json(jsonld_path)
    context = data.get("@context", {})
    if not isinstance(context, dict):
        raise ValueError("Expected @context to be a JSON object (dict).")

    graph = data.get("@graph", [])
    if not isinstance(graph, list):
        raise ValueError("Expected @graph to be a list.")

    # 1) Canonicalize all nodes, index by URI and by node_id
    all_nodes_by_uri: Dict[str, Dict[str, Any]] = {}
    all_nodes_by_node_id: Dict[str, Dict[str, Any]] = {}
    nodes_by_suffix: Dict[str, List[Dict[str, Any]]] = {}

    for raw in graph:
        if not isinstance(raw, dict):
            continue
        canon = _canonicalize_node(raw, context)
        uri = canon["uri"]
        node_id = canon["node_id"]

        all_nodes_by_uri[uri] = canon
        all_nodes_by_node_id[node_id] = canon

        sfx = _uri_suffix(uri)
        if sfx:
            nodes_by_suffix.setdefault(sfx, []).append(canon)

    # 2) Build defenses_by_d3fend_id (only nodes that have d3f:d3fend-id)
    defenses_by_d3fend_id: Dict[str, Dict[str, Any]] = {}
    for canon in all_nodes_by_uri.values():
        d3id = canon.get("d3fend_id")
        if not d3id:
            continue

        defenses_by_d3fend_id[d3id] = {
            "d3fend_id": d3id,
            "node_id": canon["node_id"],
            "uri": canon["uri"],
            "name": canon["name"],
            "definition": canon["definition"],
            "types": canon["types"],
            # Keep structured parts:
            "relations": canon["relations"],
            "kb": {
                "article": canon["raw_properties"].get("d3f:kb-article"),
                "references": _safe_list(canon["raw_properties"].get("d3f:kb-reference")),
            },
            # Will be filled from CSV
            "attack_mappings": [],
            "mapping_stats": {"rows": 0},
            # Full raw props preserved
            "raw_properties": canon["raw_properties"],
        }

    # Helper: find defense record given CSV def_tech URI
    def find_defense_by_def_tech_uri(def_tech_uri: str) -> Optional[Dict[str, Any]]:
        if not def_tech_uri:
            return None

        # Direct URI hit
        node = all_nodes_by_uri.get(def_tech_uri)
        if node and node.get("d3fend_id") and node["d3fend_id"] in defenses_by_d3fend_id:
            return defenses_by_d3fend_id[node["d3fend_id"]]

        # Fallback: match by suffix (#TokenBinding) if URI differs (rare)
        sfx = _uri_suffix(def_tech_uri)
        if not sfx:
            return None
        cands = nodes_by_suffix.get(sfx, [])
        for c in cands:
            d3id = c.get("d3fend_id")
            if d3id and d3id in defenses_by_d3fend_id:
                return defenses_by_d3fend_id[d3id]
        return None

    # 3) Parse CSV and attach mappings to the right defense
    for row in _read_csv_rows(csv_path):
        def_tech_uri = row.get("def_tech", "")
        defense = find_defense_by_def_tech_uri(def_tech_uri)
        if defense is None:
            # Not a D3FEND technique row (could be other ontology entities) → skip
            continue

        mapping = {
            # Defensive side (labels + URIs)
            "def_tech_label": row.get("def_tech_label", ""),
            "def_tech_uri": row.get("def_tech", ""),
            "def_tactic_label": row.get("def_tactic_label", ""),
            "def_tactic_uri": row.get("def_tactic", ""),
            "def_tactic_rel_label": row.get("def_tactic_rel_label", ""),
            "def_tactic_rel_uri": row.get("def_tactic_rel", ""),
            # Artifacts (defensive + offensive)
            "def_artifact_rel_label": row.get("def_artifact_rel_label", ""),
            "def_artifact_rel_uri": row.get("def_artifact_rel", ""),
            "def_artifact_label": row.get("def_artifact_label", ""),
            "def_artifact_uri": row.get("def_artifact", ""),
            "off_artifact_rel_label": row.get("off_artifact_rel_label", ""),
            "off_artifact_rel_uri": row.get("off_artifact_rel", ""),
            "off_artifact_label": row.get("off_artifact_label", ""),
            "off_artifact_uri": row.get("off_artifact", ""),
            # ATT&CK side
            "attack_technique_id": row.get("off_tech_id", ""),
            "attack_technique_label": row.get("off_tech_label", ""),
            "attack_technique_uri": row.get("off_tech", ""),
            "attack_parent_label": row.get("off_tech_parent_label", ""),
            "attack_parent_uri": row.get("off_tech_parent", ""),
            "attack_parent_is_toplevel": row.get("off_tech_parent_is_toplevel", ""),
            "attack_tactic_label": row.get("off_tactic_label", ""),
            "attack_tactic_uri": row.get("off_tactic", ""),
            "attack_tactic_rel_label": row.get("off_tactic_rel_label", ""),
            "attack_tactic_rel_uri": row.get("off_tactic_rel", ""),
            # Extra (helps debugging)
            "top_def_tech_label": row.get("top_def_tech_label", ""),
            "query_def_tech_label": row.get("query_def_tech_label", ""),
        }

        defense["attack_mappings"].append(mapping)
        defense["mapping_stats"]["rows"] += 1

    # 4) Build JSONL list (one record per defense)
    jsonl_records: List[Dict[str, Any]] = []
    for d3id, rec in sorted(defenses_by_d3fend_id.items(), key=lambda kv: kv[0]):
        jsonl_records.append(rec)

    # 5) Build big JSON
    out_json: Dict[str, Any] = {
        "meta": {
            "source_ontology": os.path.basename(jsonld_path),
            "source_mappings": os.path.basename(csv_path),
            "generated_at_utc": _utc_now_iso(),
            "format": "d3fend-normalized-v1",
            "notes": [
                "defenses_by_d3fend_id includes ONLY nodes that have d3f:d3fend-id.",
                "attack_mappings are attached by joining CSV.def_tech (full URI) -> ontology node URI.",
                "relations contains only @id-based links extracted from raw_properties.",
            ],
        },
        "namespaces": context,
        "counts": {
            "total_nodes_in_graph": len(graph),
            "total_nodes_indexed_by_uri": len(all_nodes_by_uri),
            "defenses_with_d3fend_id": len(defenses_by_d3fend_id),
            "jsonl_records": len(jsonl_records),
        },
        "defenses_by_d3fend_id": defenses_by_d3fend_id,
    }

    if include_all_nodes:
        out_json["all_nodes_by_uri"] = all_nodes_by_uri

    return out_json, jsonl_records


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def _write_jsonl(path: str, records: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False))
            f.write("\n")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--csv",
        required=True,
        help="Path to d3fend-full-mappings.csv",
    )
    p.add_argument(
        "--jsonld",
        required=True,
        help="Path to d3fend.json (JSON-LD ontology)",
    )
    p.add_argument(
        "--out-json",
        required=True,
        help="Output path for the consolidated JSON file",
    )
    p.add_argument(
        "--out-jsonl",
        required=True,
        help="Output path for the defenses JSONL file",
    )
    p.add_argument(
        "--include-all-nodes",
        action="store_true",
        help="Include a full all_nodes_by_uri index in the big JSON (large output).",
    )

    args = p.parse_args()

    out_json, jsonl_records = build_outputs(
        jsonld_path=args.jsonld,
        csv_path=args.csv,
        include_all_nodes=args.include_all_nodes,
    )

    _write_json(args.out_json, out_json)
    _write_jsonl(args.out_jsonl, jsonl_records)

    print("✅ Done")
    print(f"  JSON : {args.out_json}")
    print(f"  JSONL: {args.out_jsonl}")
    print(f"  Defenses: {out_json['counts']['defenses_with_d3fend_id']}")
    print(f"  Total nodes indexed: {out_json['counts']['total_nodes_indexed_by_uri']}")
    if args.include_all_nodes:
        print("  Included all_nodes_by_uri (large).")


if __name__ == "__main__":
    main()
