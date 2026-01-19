# src/mitre_expert/llm/mitre_docqa.py

from __future__ import annotations

import argparse
import re
import sys
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from mitre_expert.rag.query_chroma import (
    auto_search_mitre_chunks,
    resolve_best_technique,
    get_mitre_chunks_by_filter,
)
from mitre_expert.llm.local_llm import generate_answer
from mitre_expert.llm.prompts import DOCQA_SYSTEM_PROMPT

# Regex for mitigation IDs like M1052
MIT_ID_RE = re.compile(r"\bM\d{4}\b")

# Regex for technique IDs like T1548 or T1059.001
TECHID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


def _split_csv_field(v: object) -> List[str]:
    """
    Normalize a metadata field that might be:
      - CSV string: "a, b, c"
      - list / tuple / set
      - None
      - arbitrary object
    into a clean List[str].
    """
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if x and str(x).strip()]
    if isinstance(v, str):
        return [x.strip() for x in v.split(",") if x.strip()]
    s = str(v).strip()
    return [s] if s else []


@lru_cache(maxsize=2048)
def _fetch_tactics_platforms_for_technique(technique_id: str) -> Tuple[List[str], List[str]]:
    """
    Cached metadata lookup for a technique_id -> (tactic_ids, platforms)
    using a deterministic .get() call.
    """
    tid = (technique_id or "").upper()
    if not tid:
        return [], []

    res = get_mitre_chunks_by_filter(where={"technique_id": tid}, limit=1)
    metas = res.get("metadatas", [[]])[0]
    if not metas:
        return [], []

    meta = metas[0] or {}

    raw_tactics = meta.get("tactic_ids") or ""
    raw_platforms = meta.get("platforms") or ""

    tactic_ids = _split_csv_field(raw_tactics)
    platforms = _split_csv_field(raw_platforms)

    return tactic_ids, platforms


def extract_meta_from_context(context: str) -> Dict[str, List[str]]:
    """
    Extract techniques, tactics, platforms, and mitigations from the MITRE CONTEXT.

    Strategy:
      - Technique IDs from TECHID_RE in the context text.
      - For each technique_id, fetch one chunk via get_mitre_chunks_by_filter(..., limit=1)
        and read tactic_ids/platforms from metadata (cached).
      - Mitigation IDs via MIT_ID_RE across the context.
    """
    if not context:
        return {"techniques": [], "tactics": [], "platforms": [], "mitigations": []}

    # Technique IDs present in the context
    techniques = sorted(set(t.upper() for t in TECHID_RE.findall(context)))

    all_tactics: List[str] = []
    all_platforms: List[str] = []

    for tid in techniques:
        tacts, plats = _fetch_tactics_platforms_for_technique(tid)
        all_tactics.extend(tacts)
        all_platforms.extend(plats)

    def _dedupe(seq: List[str]) -> List[str]:
        seen: set[str] = set()
        out: List[str] = []
        for s in seq:
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out

    tactics = _dedupe(all_tactics)
    platforms = _dedupe(all_platforms)

    # Mitigation IDs present in the context
    mit_ids = sorted(set(MIT_ID_RE.findall(context)))

    return {
        "techniques": techniques,
        "tactics": tactics,
        "platforms": platforms,
        "mitigations": mit_ids,
    }


def _guess_mitigation_name_from_text(doc: str) -> str:
    if not doc:
        return ""
    first_line = doc.split("\n", 1)[0].strip()
    for sep in [".", ":", " refers to "]:
        if sep in first_line:
            first_line = first_line.split(sep, 1)[0].strip()
            break
    if " is " in first_line:
        first_line = first_line.split(" is ", 1)[0].strip()
    return first_line


def _question_mentions_any_tech_id(q: str) -> bool:
    return bool(TECHID_RE.search(q or ""))


def _is_explanation_question(q: str) -> bool:
    """
    Detect if the question is asking to explain/describe a technique.
    
    Examples:
    - "What is T1059?"
    - "Explain T1059"
    - "Tell me about T1059"
    - "Describe Command and Scripting Interpreter"
    """
    ql = (q or "").strip().lower()
    if not ql:
        return False
    
    # Strong indicators of explanation questions
    explanation_patterns = [
        "what is ",
        "what's ",
        "explain ",
        "describe ",
        "tell me about ",
        "overview of ",
        "summary of ",
        "what does ",
        "how does ",
        "what are the ",  # "what are the sub-techniques"
    ]
    
    for pattern in explanation_patterns:
        if ql.startswith(pattern) or f" {pattern}" in ql:
            return True
    
    # If question mentions a technique ID and doesn't have detection/mitigation keywords
    if _question_mentions_any_tech_id(q):
        detection_keywords = ["detect", "detection", "hunt", "rule", "sigma", "log", "telemetry"]
        mitigation_keywords = ["mitigat", "prevent", "countermeasure", "remediat", "defense"]
        
        has_detection = any(kw in ql for kw in detection_keywords)
        has_mitigation = any(kw in ql for kw in mitigation_keywords)
        
        # Simple questions like "T1059?" or "What is T1059?" without other keywords
        if not has_detection and not has_mitigation:
            return True
    
    return False


def _is_mitigation_enumeration_question(q: str) -> bool:
    """
    True if the user is asking to list / enumerate mitigations.

    IMPORTANT:
    - No hardcoded technique IDs.
    - Triggers on any technique id (T#### / T####.###) or clear "list mitigations" patterns.
    """
    ql = (q or "").strip().lower()
    if not ql:
        return False

    # strong cues
    if "which mitigations" in ql:
        return True
    if ql.startswith("list mitigations") or ql.startswith("list mitigation"):
        return True
    if ql.startswith("mitigations for") or ql.startswith("mitigation for"):
        return True

    # softer cues: "mitigations" + technique id somewhere
    if ("mitigations" in ql or "mitigation" in ql) and _question_mentions_any_tech_id(q):
        return True

    return False


def _question_wants_mitigations(q: str) -> bool:
    """
    Broader than enumeration: includes "how to mitigate" type questions.
    """
    ql = (q or "").strip().lower()
    if not ql:
        return False

    if _is_mitigation_enumeration_question(q):
        return True

    # e.g. "how to mitigate T1110", "how do we prevent", "countermeasures"
    if "how to mitigate" in ql or "how do i mitigate" in ql or "how do we mitigate" in ql:
        return True
    if (
        "prevent" in ql
        or "mitigate" in ql
        or "countermeasure" in ql
        or "remediation" in ql
    ) and _question_mentions_any_tech_id(q):
        return True

    return False


def _extract_mitigation_ids_from_context(context: str) -> List[str]:
    if not context:
        return []
    found = MIT_ID_RE.findall(context)
    seen = set()
    out: List[str] = []
    for m in found:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def _extract_mitigation_ids_from_answer(ans: str) -> List[str]:
    if not ans:
        return []
    found = MIT_ID_RE.findall(ans)
    seen = set()
    out: List[str] = []
    for m in found:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def build_mitre_context(question: str, topk: int = 8) -> str:
    """
    Build a context block for the MITRE-DocQA model.

    IMPROVED: For explanation questions ("What is T1059?"), always fetch:
      1. The description chunk (deterministically)
      2. Procedure examples (if available)
      3. Then fill remaining slots with semantic search
    
    For mitigation enumeration questions:
      - resolve technique_id
      - fetch 1 description chunk deterministically
      - fetch ALL mitigation chunks deterministically (subject to hard cap)
    """
    want_mitigations_enum = _is_mitigation_enumeration_question(question)
    want_explanation = _is_explanation_question(question)

    best = resolve_best_technique(question, max_results=3)
    technique_id = best.id.upper() if best and best.id else None

    lines: List[str] = []

    # =========================================================================
    # Mode 1: Mitigation enumeration (existing logic)
    # =========================================================================
    if want_mitigations_enum and technique_id:
        lines.append(f"Detected techniques: {technique_id}")
        lines.append("")

        # Description (useful context)
        desc = get_mitre_chunks_by_filter(
            where={"technique_id": technique_id, "section": "description"},
            limit=1,
        )
        desc_docs = desc.get("documents", [[]])[0]
        desc_metas = desc.get("metadatas", [[]])[0]
        if desc_docs and desc_metas:
            ddoc = desc_docs[0]
            dmeta = desc_metas[0]
            tname = dmeta.get("technique_name", "")
            header = f"[{technique_id} {('- ' + tname) if tname else ''} | description]"
            lines.append(header)
            lines.append(ddoc)
            lines.append("")

        # ALL mitigations (limit=None; query_chroma may apply a safety cap)
        mit = get_mitre_chunks_by_filter(
            where={"technique_id": technique_id, "section": "mitigation"},
            limit=None,
        )
        docs: List[str] = mit.get("documents", [[]])[0]
        metas: List[Dict[str, Any]] = mit.get("metadatas", [[]])[0]
        ids: List[str] = mit.get("ids", [[]])[0]

        def _mit_sort_key(item: Tuple[str, str, Dict[str, Any]]) -> Tuple[int, str]:
            _, _, m = item
            mid = (m.get("mitigation_id") or "").strip()
            if mid.startswith("M") and mid[1:].isdigit():
                return (int(mid[1:]), mid)
            return (10**9, mid or "")

        packed = list(zip(ids, docs, metas))
        packed.sort(key=_mit_sort_key)

        for cid, doc, meta in packed:
            mid = meta.get("mitigation_id")
            mname = meta.get("mitigation_name") or ""
            if not mid:
                m = MIT_ID_RE.search(cid or "")
                if m:
                    mid = m.group(0)
            if mid and not mname:
                mname = _guess_mitigation_name_from_text(doc)

            parts = [technique_id, "| mitigation"]
            if mid:
                parts.append(mid)
            if mname:
                parts.append(f"- {mname}")
            header = " ".join(parts)

            lines.append(header)
            lines.append(doc)
            lines.append("")

        return "\n".join(lines)

    # =========================================================================
    # Mode 2: Explanation question - prioritize description + procedure_example
    # =========================================================================
    if want_explanation and technique_id:
        lines.append(f"Detected techniques: {technique_id}")
        lines.append("")
        
        used_chunk_ids: set = set()
        chunks_added = 0
        
        # 2a. Always fetch description first
        desc = get_mitre_chunks_by_filter(
            where={"technique_id": technique_id, "section": "description"},
            limit=1,
        )
        desc_docs = desc.get("documents", [[]])[0]
        desc_metas = desc.get("metadatas", [[]])[0]
        desc_ids = desc.get("ids", [[]])[0]
        
        if desc_docs and desc_metas:
            ddoc = desc_docs[0]
            dmeta = desc_metas[0]
            did = desc_ids[0] if desc_ids else ""
            tname = dmeta.get("technique_name", "")
            header = f"[{technique_id} {('- ' + tname) if tname else ''} | description]"
            lines.append(header)
            lines.append(ddoc)
            lines.append("")
            used_chunk_ids.add(did)
            chunks_added += 1
        
        # 2b. Fetch procedure examples (real-world usage)
        proc = get_mitre_chunks_by_filter(
            where={"technique_id": technique_id, "section": "procedure_example"},
            limit=3,
        )
        proc_docs = proc.get("documents", [[]])[0]
        proc_metas = proc.get("metadatas", [[]])[0]
        proc_ids = proc.get("ids", [[]])[0]
        
        for pid, pdoc, pmeta in zip(proc_ids, proc_docs, proc_metas):
            if chunks_added >= topk:
                break
            if pid in used_chunk_ids:
                continue
            tname = pmeta.get("technique_name", "")
            header = f"[{technique_id} {('- ' + tname) if tname else ''} | procedure_example]"
            lines.append(header)
            lines.append(pdoc)
            lines.append("")
            used_chunk_ids.add(pid)
            chunks_added += 1
        
        # 2c. Fill remaining slots with semantic search (excluding already-used chunks)
        remaining = topk - chunks_added
        if remaining > 0:
            result: Dict[str, Any] = auto_search_mitre_chunks(query=question, k=remaining + 5)
            sem_docs = result.get("documents", [[]])[0]
            sem_metas = result.get("metadatas", [[]])[0]
            sem_ids = result.get("ids", [[]])[0]
            
            for sid, sdoc, smeta in zip(sem_ids, sem_docs, sem_metas):
                if chunks_added >= topk:
                    break
                if sid in used_chunk_ids:
                    continue
                
                tid = smeta.get("technique_id", "unknown")
                tname = smeta.get("technique_name", "")
                section = smeta.get("section", smeta.get("chunk_type", smeta.get("type", "unknown")))
                
                header = f"[{tid} {('- ' + tname) if tname else ''} | {section}]"
                lines.append(header)
                lines.append(sdoc)
                lines.append("")
                used_chunk_ids.add(sid)
                chunks_added += 1
        
        return "\n".join(lines)

    # Default mode (semantic top-k)
    result: Dict[str, Any] = auto_search_mitre_chunks(query=question, k=topk)
    docs: List[str] = result.get("documents", [[]])[0]
    metas: List[Dict[str, Any]] = result.get("metadatas", [[]])[0]
    ids: List[str] = result.get("ids", [[]])[0]

    technique_ids = {m.get("technique_id", "unknown") for m in metas}
    techniques_str = ", ".join(sorted(t for t in technique_ids if t != "unknown"))

    if techniques_str:
        lines.append(f"Detected techniques: {techniques_str}")
        lines.append("")

    for cid, doc, meta in zip(ids, docs, metas):
        tid = meta.get("technique_id", "unknown")
        tname = meta.get("technique_name", "")
        section = meta.get("section", meta.get("chunk_type", meta.get("type", "unknown")))

        mit_id: Optional[str] = meta.get("mitigation_id")
        if not mit_id:
            m = MIT_ID_RE.search(cid or "")
            if m:
                mit_id = m.group(0)

        mit_name: str = meta.get("mitigation_name") or ""
        if mit_id and not mit_name:
            mit_name = _guess_mitigation_name_from_text(doc)

        if section == "mitigation" or mit_id:
            parts = [tid, "| mitigation"]
            if mit_id:
                parts.append(mit_id)
            if mit_name:
                parts.append(f"- {mit_name}")
            header = " ".join(parts)
        else:
            header = f"[{tid} {('- ' + tname) if tname else ''} | {section}]"

        lines.append(header)
        lines.append(doc)
        lines.append("")

    return "\n".join(lines)


def answer_mitre_docqa(
    question: str,
    topk: int = 8,
    temperature: float = 0.5,
    context: str | None = None,
) -> str:
    """
    High-level MITRE-DocQA answer function.

    Behavior:
    - Only request/format a Mitigations section when the QUESTION actually asks for mitigations.
      This prevents the model from "trying" to produce mitigations for unrelated questions.
    - Still includes a completeness backstop for *enumeration* questions.
    """
    if context is None:
        context = build_mitre_context(question, topk=topk)

    want_mitigations = _question_wants_mitigations(question)
    want_enum = _is_mitigation_enumeration_question(question)

    if want_mitigations:
        task_block = """
TASK:
1. First, briefly explain the main technique(s) in 2–4 sentences, using ONLY the MITRE CONTEXT.
2. Then, provide a **Mitigations** section that lists each mitigation as bullets
   in this exact format:

   - [<Mitigation_ID>] <Mitigation_Name>: <1–3 sentence description>

   For each mitigation:
   - Base your description ONLY on the MITRE CONTEXT text for that mitigation.
   - If the context includes concrete implementation details, mention at least one.
     (Do NOT invent tools/products/settings not present in the MITRE CONTEXT.)

OUTPUT RULES:
- Only list mitigations that appear in the MITRE CONTEXT.
- Do NOT invent mitigation IDs or names.
- If no mitigations are available in the context, add a line saying:
  "No mitigations are provided in the given MITRE context."
""".strip()
    else:
        task_block = """
TASK:
- Briefly answer the QUESTION in 2–6 sentences using ONLY the MITRE CONTEXT.
- Do NOT add a "Mitigations" section unless the QUESTION explicitly asks for mitigations.
- If the needed detail is not in the context, say it is not specified.
""".strip()

    user_content = f"""
You are a SOC analyst using MITRE ATT&CK as your ONLY knowledge source.

You are given MITRE ATT&CK context for one or more techniques.

STRICT RULES:
- You MUST use ONLY the information explicitly present in the MITRE CONTEXT below.
- Do NOT invent extra examples, causes, mitigations, products, or techniques that are not mentioned in the MITRE CONTEXT.
- Stay close to the wording and intent of the MITRE CONTEXT.
- If the context does not contain a detail, say that it is not specified instead of guessing.

{task_block}

MITRE CONTEXT:
{context}

QUESTION:
{question}
""".strip()

    answer = generate_answer(
        system_prompt=DOCQA_SYSTEM_PROMPT,
        user_content=user_content,
        max_new_tokens=768,
        temperature=temperature,
    )

    # Completeness backstop ONLY for mitigation ENUMERATION questions
    if want_enum:
        ctx_mids = _extract_mitigation_ids_from_context(context)
        ans_mids = _extract_mitigation_ids_from_answer(answer)
        missing = [m for m in ctx_mids if m not in set(ans_mids)]
        if missing:
            add = "\n\n**Mitigations (additional from context)**\n"
            for mid in missing:
                add += f"- [{mid}] (present in context)\n"
            answer = answer.rstrip() + add

    return answer


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MITRE-DocQA LLM with RAG over Chroma (local HF model).",
    )
    parser.add_argument(
        "question",
        nargs="+",
        help="User question in natural language.",
    )
    parser.add_argument(
        "-k",
        "--topk",
        type=int,
        default=8,
        help="Number of RAG chunks to retrieve (default: 8).",
    )
    parser.add_argument(
        "--temp",
        "--temperature",
        dest="temperature",
        type=float,
        default=0.5,
        help="Sampling temperature (default: 0.5).",
    )
    parser.add_argument(
        "--show-context",
        action="store_true",
        help="If set, print the RAG context before the answer.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    question = " ".join(args.question)

    print(f"[docqa] Question: {question!r}")

    try:
        context = build_mitre_context(question, topk=args.topk)
    except Exception as e:
        print(f"[docqa] ERROR while building context: {e}")
        sys.exit(1)

    if args.show_context:
        print("\n=== RAG CONTEXT ===")
        print(context)

    try:
        answer = answer_mitre_docqa(
            question=question,
            topk=args.topk,
            temperature=args.temperature,
            context=context,
        )
    except Exception as e:
        print(f"[docqa] ERROR while generating answer: {e}")
        sys.exit(1)

    print("\n=== ANSWER ===")
    print(answer)


if __name__ == "__main__":
    main()