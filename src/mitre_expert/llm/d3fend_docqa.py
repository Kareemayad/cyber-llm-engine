# src/mitre_expert/llm/d3fend_docqa.py

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional

from mitre_expert.rag.query_chroma import search_d3fend_chunks
from mitre_expert.llm.local_llm import generate_answer
from mitre_expert.llm.prompts import D3FEND_SYSTEM_PROMPT


def build_d3fend_context(question: str, topk: int = 8) -> str:
    """
    Pull top-k D3FEND chunks from the D3FEND Chroma collection and format as context.
    This is intentionally generic because D3FEND chunk metadata keys may vary.
    """
    res: Dict[str, Any] = search_d3fend_chunks(query=question, k=topk)

    docs: List[str] = res.get("documents", [[]])[0]
    metas: List[Dict[str, Any]] = res.get("metadatas", [[]])[0]
    ids: List[str] = res.get("ids", [[]])[0]

    lines: List[str] = []
    for cid, doc, meta in zip(ids, docs, metas):
        meta = meta or {}

        # Try a few common key options; harmless if missing
        section = meta.get("section") or meta.get("chunk_type") or meta.get("type") or "unknown"
        d3_id = meta.get("d3fend_id") or meta.get("defense_id") or meta.get("id") or ""
        name = meta.get("d3fend_name") or meta.get("defense_name") or meta.get("name") or ""

        header = f"[{d3_id} {('- ' + name) if name else ''} | {section}]".strip()
        lines.append(header)
        lines.append(doc or "")
        lines.append("")

    return "\n".join(lines).strip()


def answer_d3fend_docqa(
    question: str,
    topk: int = 8,
    temperature: float = 0.3,
    context: Optional[str] = None,
) -> str:
    if context is None:
        context = build_d3fend_context(question, topk=topk)

    user_content = f"""
You are a SOC analyst.

STRICT RULES:
- You MUST use ONLY the information explicitly present in the D3FEND CONTEXT.
- Do NOT invent IDs, names, products, or steps not present in the context.
- If the context does not contain the needed detail, say it is not specified.

TASK:
- Answer the QUESTION in 3–10 sentences using only the D3FEND context.
- If the question asks for a list, use bullet points.

D3FEND CONTEXT:
{context}

QUESTION:
{question}
""".strip()

    return generate_answer(
        system_prompt=D3FEND_SYSTEM_PROMPT,
        user_content=user_content,
        max_new_tokens=768,
        temperature=temperature,
    )


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="D3FEND DocQA with RAG over Chroma.")
    p.add_argument("question", nargs="+", help="Natural language question.")
    p.add_argument("-k", "--topk", type=int, default=8, help="Number of chunks to retrieve (default 8).")
    p.add_argument("--temp", type=float, default=0.3, help="Temperature (default 0.3).")
    p.add_argument("--show-context", action="store_true", help="Print the RAG context before the answer.")
    return p.parse_args(argv)


def main(argv: List[str] | None = None) -> None:
    args = parse_args(argv or sys.argv[1:])
    q = " ".join(args.question)

    print(f"[d3fend_docqa] Question: {q!r}")

    try:
        ctx = build_d3fend_context(q, topk=args.topk)
    except Exception as e:
        print(f"[d3fend_docqa] ERROR while building context: {e}")
        sys.exit(1)

    if args.show_context:
        print("\n=== RAG CONTEXT ===\n")
        print(ctx)

    try:
        ans = answer_d3fend_docqa(q, topk=args.topk, temperature=args.temp, context=ctx)
    except Exception as e:
        print(f"[d3fend_docqa] ERROR while generating answer: {e}")
        sys.exit(1)

    print("\n=== ANSWER ===\n")
    print(ans)


if __name__ == "__main__":
    main()
