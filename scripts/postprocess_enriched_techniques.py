import json
from collections import OrderedDict

IN_PATH  = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/techniques_full_enriched.jsonl"
OUT_PATH = "/Users/kareemayad/Documents/Kareem Ayad Development/cyber-llm-engine/data/processed/mitre/techniques_full_enriched_v2.jsonl"

def dedupe_preserve_order(items):
    seen = set()
    out = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out

def main():
    total = 0
    with_dc = 0

    with open(IN_PATH, "r", encoding="utf-8") as fin, open(OUT_PATH, "w", encoding="utf-8") as fout:
        for line in fin:
            t = json.loads(line)
            total += 1

            dcs = t.get("data_components") or []
            if dcs:
                with_dc += 1

            # data_component_ids
            dc_ids = [dc.get("data_component_id") for dc in dcs if dc.get("data_component_id")]
            t["data_component_ids"] = dedupe_preserve_order(dc_ids)

            # log_source_names (dedup)
            ls_names = []
            for dc in dcs:
                for ls in (dc.get("log_sources") or []):
                    name = ls.get("name")
                    if name:
                        ls_names.append(name)
            t["log_source_names"] = dedupe_preserve_order(ls_names)

            fout.write(json.dumps(t, ensure_ascii=False) + "\n")

    print(f"[ok] total techniques: {total}")
    print(f"[ok] techniques with data components: {with_dc}")
    print(f"[ok] wrote: {OUT_PATH}")

if __name__ == "__main__":
    main()
