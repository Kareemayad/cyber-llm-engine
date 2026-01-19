#!/usr/bin/env python3
"""
Debug script to test the DocQA pipeline directly.

Run from your project root:
    python debug_docqa.py "What is T1059?"
"""

import sys

def main():
    question = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "What is T1059?"
    
    print(f"=" * 60)
    print(f"Question: {question}")
    print(f"=" * 60)
    
    # Import the docqa functions
    from mitre_expert.llm.mitre_docqa import build_mitre_context, answer_mitre_docqa
    
    # Build context
    print("\n[1] Building MITRE context...")
    context = build_mitre_context(question, topk=8)
    
    print(f"\n[2] Context length: {len(context)} chars")
    print(f"\n--- CONTEXT (first 2000 chars) ---")
    print(context[:2000])
    if len(context) > 2000:
        print(f"\n... ({len(context) - 2000} more chars)")
    
    # Generate answer
    print(f"\n[3] Generating answer...")
    answer = answer_mitre_docqa(
        question=question,
        topk=8,
        temperature=0.2,
        context=context,
    )
    
    print(f"\n--- ANSWER ---")
    print(answer)
    print(f"\n[Answer length: {len(answer)} chars]")


if __name__ == "__main__":
    main()