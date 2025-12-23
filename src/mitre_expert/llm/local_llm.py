# src/mitre_expert/llm/local_llm.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple, Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Default: <repo_root>/src/mitre_expert/models/llama3.1-8b-instruct
DEFAULT_MODEL_DIR = (
    Path(__file__).resolve()
    .parents[1]  # .../src/mitre_expert
    / "models"
    / "llama3.1-8b-instruct"
)

MODEL_PATH = os.getenv("MITRE_DOCQA_MODEL_PATH", str(DEFAULT_MODEL_DIR))

# Optional env overrides
ENV_MAX_CONTEXT = os.getenv("MITRE_LLM_MAX_CONTEXT")
ENV_MAX_NEW_TOKENS = os.getenv("MITRE_LLM_MAX_NEW_TOKENS")

# Device / dtype selection
if torch.backends.mps.is_available():
    # IMPORTANT: use float32 on MPS to avoid instability / gibberish for long prompts
    DEVICE = torch.device("mps")
    DTYPE = torch.float32
elif torch.cuda.is_available():
    DEVICE = torch.device("cuda")
    # bfloat16 tends to be more stable if supported, else fp16
    if torch.cuda.is_bf16_supported():
        DTYPE = torch.bfloat16
    else:
        DTYPE = torch.float16
else:
    DEVICE = torch.device("cpu")
    DTYPE = torch.float32

_LLM_LOADED = False
_TOKENIZER: Optional[AutoTokenizer] = None
_MODEL: Optional[AutoModelForCausalLM] = None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load_llm() -> Tuple[AutoTokenizer, AutoModelForCausalLM]:
    """
    Lazy-load the tokenizer/model once per process.
    """
    global _LLM_LOADED, _TOKENIZER, _MODEL

    if _LLM_LOADED and _TOKENIZER is not None and _MODEL is not None:
        return _TOKENIZER, _MODEL

    model_path = MODEL_PATH
    print(f"[local_llm] Loading model from: {model_path}")
    print(f"[local_llm] Using device: {DEVICE} (dtype={DTYPE})")

    tokenizer = AutoTokenizer.from_pretrained(
        model_path,
        local_files_only=True,
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        local_files_only=True,
        torch_dtype=DTYPE,
    )

    model.to(DEVICE)
    model.eval()

    _TOKENIZER = tokenizer
    _MODEL = model
    _LLM_LOADED = True

    # Show if we have a chat template
    has_template = hasattr(tokenizer, "apply_chat_template")
    print(f"[local_llm] Tokenizer chat template available: {has_template}")

    return tokenizer, model


# ---------------------------------------------------------------------------
# Generation helper
# ---------------------------------------------------------------------------

def _resolve_max_context(model: AutoModelForCausalLM) -> int:
    """
    Pick a safe max context length.
    Priority:
    - MITRE_LLM_MAX_CONTEXT env (if set)
    - model.config.max_position_embeddings
    - tokenizer.model_max_length fallback (handled indirectly)
    - default 8192
    """
    if ENV_MAX_CONTEXT is not None:
        try:
            val = int(ENV_MAX_CONTEXT)
            if val > 0:
                return val
        except ValueError:
            pass

    cfg = model.config
    if hasattr(cfg, "max_position_embeddings") and cfg.max_position_embeddings:
        return int(cfg.max_position_embeddings)

    # Some models store effective context in other fields, but as a safe default:
    return 8192


def generate_answer(
    system_prompt: str,
    user_content: str,
    max_new_tokens: int = 256,
    temperature: float | None = None,
    top_p: float = 0.9,
    repetition_penalty: float = 1.05,
) -> str:
    """
    Generate an answer using the local LLaMA model with a simple
    system+user chat-style prompt.

    Notes:
    - If temperature is None -> greedy / deterministic decoding (recommended for DocQA).
    - If temperature is not None -> sampling is enabled with the given temperature/top_p.
    """
    tokenizer, model = _load_llm()

    # Allow global override for max_new_tokens if needed for safety
    if ENV_MAX_NEW_TOKENS is not None:
        try:
            env_max = int(ENV_MAX_NEW_TOKENS)
            if env_max > 0:
                max_new_tokens = min(max_new_tokens, env_max)
        except ValueError:
            pass

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]

    # Use chat template if available (LLaMA 3.x style)
    if hasattr(tokenizer, "apply_chat_template"):
        prompt_text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        use_chat_template = True
    else:
        # Fallback: simple tagged format
        prompt_text = (
            f"[SYSTEM]\n{system_prompt}\n\n"
            f"[USER]\n{user_content}\n\n"
            f"[ASSISTANT]\n"
        )
        use_chat_template = False

    print(f"[local_llm] Using chat template: {use_chat_template}")
    print(f"[local_llm] Prompt length (chars): {len(prompt_text)}")

    # Tokenize without automatic truncation; we handle context size ourselves
    inputs = tokenizer(
        prompt_text,
        return_tensors="pt",
        truncation=False,
    )

    input_ids = inputs["input_ids"].to(DEVICE)
    attention_mask = inputs.get("attention_mask", None)
    if attention_mask is not None:
        attention_mask = attention_mask.to(DEVICE)

    # -----------------------------------------------------------------------
    # Context window safety: truncate from the left if input is too long
    # -----------------------------------------------------------------------
    max_context = _resolve_max_context(model)
    max_input_tokens = max_context - max_new_tokens

    if input_ids.shape[1] > max_input_tokens:
        # keep only the tail of the prompt (most recent information)
        cut_from = input_ids.shape[1] - max_input_tokens
        input_ids = input_ids[:, cut_from:]
        if attention_mask is not None:
            attention_mask = attention_mask[:, cut_from:]
        print(
            f"[local_llm] Truncated input to {max_input_tokens} tokens "
            f"(max_context={max_context}, max_new_tokens={max_new_tokens})"
        )

    # -----------------------------------------------------------------------
    # Generation
    # -----------------------------------------------------------------------
    gen_kwargs = {
        "input_ids": input_ids,
        "attention_mask": attention_mask,
        "max_new_tokens": max_new_tokens,
        "pad_token_id": tokenizer.pad_token_id,
        "eos_token_id": tokenizer.eos_token_id,
    }

    if temperature is None:
        # deterministic / greedy decoding (best for knowledge-style DocQA)
        gen_kwargs.update(
            dict(
                do_sample=False,
            )
        )
    else:
        # enable sampling explicitly if user asks for it
        gen_kwargs.update(
            dict(
                do_sample=True,
                temperature=max(0.1, float(temperature)),
                top_p=float(top_p),
                repetition_penalty=float(repetition_penalty),
            )
        )

    # inference_mode is slightly stricter than no_grad, avoids autograd overhead
    with torch.inference_mode():
        output_ids = model.generate(**gen_kwargs)

    # Only decode newly generated tokens, not the whole prompt
    generated = output_ids[0, input_ids.shape[-1]:]
    text = tokenizer.decode(generated, skip_special_tokens=True)

    # Basic cleanup
    return text.strip()
