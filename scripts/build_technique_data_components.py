import pandas as pd
from stix2 import MemoryStore, Filter

TECH_XLSX = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/enterprise-attack-v18.1-techniques.xlsx"
DC_XLSX   = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/enterprise-attack-v18.1-datacomponents.xlsx"
STIX_JSON = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/raw/mitre/enterprise-attack-18.1.json"

OUT_OK  = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/technique_data_components.csv"
OUT_ALL = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/technique_data_components_with_unmatched.csv"


def _safe_get(obj, key, default=None):
    # stix2 objects support dict-like access; use .get when possible
    try:
        return obj.get(key, default)
    except Exception:
        try:
            return obj[key]
        except Exception:
            return default


def main():
    # --- Excel lookups: STIX ID -> ATT&CK external ID (T#### / DC####)
    tech = pd.read_excel(TECH_XLSX, sheet_name="techniques")
    dc   = pd.read_excel(DC_XLSX,   sheet_name="datacomponents")

    print(f"[debug] Excel techniques: {len(tech)}")
    print(f"[debug] Excel data components: {len(dc)}")

    tech_map = dict(zip(tech["STIX ID"], tech["ID"]))  # attack-pattern--... -> T####
    dc_map   = dict(zip(dc["STIX ID"],   dc["ID"]))    # x-mitre-data-component--... -> DC####

    # --- Load STIX bundle
    src = MemoryStore()
    src.load_from_file(STIX_JSON)

    # 1) Get DetectionStrategy -> Technique via relationship_type=detects
    rels = src.query([
        Filter("type", "=", "relationship"),
        Filter("relationship_type", "=", "detects"),
        Filter("revoked", "=", False),
    ])
    print(f"[debug] detects relationships in bundle (active): {len(rels)}")

    ds_to_tech = []  # tuples: (ds_stix_id, technique_stix_id, relationship_stix_id)
    for r in rels:
        s = r.source_ref
        t = r.target_ref
        if not (isinstance(s, str) and isinstance(t, str)):
            continue
        if s.startswith("x-mitre-detection-strategy--") and t.startswith("attack-pattern--"):
            ds_to_tech.append((s, t, r.id))

    print(f"[debug] DetectionStrategy -> Technique detects edges: {len(ds_to_tech)}")
    if not ds_to_tech:
        print("[warn] No DetectionStrategy->Technique detects edges found. Nothing to do.")
        # still write empty outputs
        pd.DataFrame([]).to_csv(OUT_ALL, index=False)
        pd.DataFrame([]).to_csv(OUT_OK, index=False)
        return

    # 2) Expand DetectionStrategy -> Analytic refs (x_mitre_analytic_refs)
    rows = []
    missing_ds = 0
    missing_analytics = 0
    missing_logrefs = 0

    # cache objects to avoid repeated lookups
    ds_cache = {}
    an_cache = {}

    for ds_id, tech_stix, rel_id in ds_to_tech:
        if ds_id not in ds_cache:
            ds_cache[ds_id] = src.get(ds_id)
        ds_obj = ds_cache[ds_id]
        if ds_obj is None:
            missing_ds += 1
            continue

        # per schema: x_mitre_analytic_refs (array of x-mitre-analytic IDs)
        analytic_refs = _safe_get(ds_obj, "x_mitre_analytic_refs", None) or _safe_get(ds_obj, "x_mitre_analytics", None)
        if not analytic_refs:
            missing_analytics += 1
            continue

        # 3) For each Analytic, get Data Component refs via x_mitre_log_source_references[]
        for an_id in analytic_refs:
            if an_id not in an_cache:
                an_cache[an_id] = src.get(an_id)
            an_obj = an_cache[an_id]
            if an_obj is None:
                missing_analytics += 1
                continue

            # per schema: x_mitre_log_source_references: [{x_mitre_data_component_ref, name, channel}, ...]
            logrefs = _safe_get(an_obj, "x_mitre_log_source_references", None) or _safe_get(an_obj, "x_mitre_log_source_reference", None)
            if not logrefs:
                missing_logrefs += 1
                continue

            for lr in logrefs:
                dc_stix = None
                name = None
                channel = None

                if isinstance(lr, dict):
                    dc_stix = lr.get("x_mitre_data_component_ref")
                    name = lr.get("name")
                    channel = lr.get("channel")

                if not (isinstance(dc_stix, str) and dc_stix.startswith("x-mitre-data-component--")):
                    continue

                rows.append({
                    # Technique
                    "technique_stix_id": tech_stix,
                    "technique_id": tech_map.get(tech_stix),
                    # Data Component
                    "data_component_stix_id": dc_stix,
                    "data_component_id": dc_map.get(dc_stix),
                    # Detection Strategy + Analytic context (useful for tracing)
                    "detection_strategy_stix_id": ds_id,
                    "detection_strategy_name": _safe_get(ds_obj, "name"),
                    "analytic_stix_id": an_id,
                    "analytic_name": _safe_get(an_obj, "name"),
                    # Log source detail (ties to the DC log sources)
                    "log_source_name": name,
                    "log_source_channel": channel,
                    # Relationship trace
                    "relationship_type": "detects",
                    "relationship_stix_id": rel_id,
                })

    out = pd.DataFrame(rows)

    # Always write ALL (even if empty)
    out.to_csv(OUT_ALL, index=False)
    print(f"[ok] Wrote ALL: {OUT_ALL} (rows={len(out)})")

    if len(out) == 0:
        print("[warn] Expanded 0 rows. This usually means:")
        print("       - detection strategies have no x_mitre_analytic_refs in your bundle, OR")
        print("       - analytics have no x_mitre_log_source_references, OR")
        print("       - the bundle is missing x-mitre-analytic objects.")
        print(f"[debug] missing_ds={missing_ds}, missing_analytics={missing_analytics}, missing_logrefs={missing_logrefs}")
        pd.DataFrame([]).to_csv(OUT_OK, index=False)
        print(f"[ok] Wrote OK : {OUT_OK} (rows=0)")
        return

    # OK = resolved technique_id + data_component_id
    out_ok = out.dropna(subset=["technique_id", "data_component_id"])
    out_ok.to_csv(OUT_OK, index=False)

    print(f"[ok] Wrote OK : {OUT_OK} (rows={len(out_ok)})")
    print(f"[debug] Unmatched rows (missing T#### or DC####): {len(out) - len(out_ok)}")
    print(f"[debug] missing_ds={missing_ds}, missing_analytics={missing_analytics}, missing_logrefs={missing_logrefs}")

    # small sanity sample
    print("[debug] Sample rows:")
    print(out_ok.head(5).to_string(index=False))


if __name__ == "__main__":
    main()
