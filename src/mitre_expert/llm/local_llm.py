# src/mitre_expert/llm/local_llm.py
"""
Local LLM inference with triple-backend support:
  - Ollama (HTTP API, easiest setup)
  - MLX (Apple Silicon optimized, recommended for Mac with local model files)
  - Transformers/PyTorch (CUDA/CPU/MPS fallback)

Configuration (via environment variables or config.py):
  MITRE_LLM_BACKEND          - "ollama", "mlx", or "transformers" (default: ollama)
  MITRE_OLLAMA_MODEL         - Ollama model name (default: llama3.1:latest)
  MITRE_OLLAMA_BASE_URL      - Ollama server URL (default: http://127.0.0.1:11434)
  MITRE_MLX_MODEL_PATH       - Path to MLX quantized model
  MITRE_HF_MODEL_PATH        - Path to HuggingFace/Transformers model
  MITRE_DOCQA_MODEL_PATH     - Fallback path for both (backward compatible)
  MITRE_LLM_MAX_CONTEXT      - Max context window (transformers only)
  MITRE_LLM_MAX_NEW_TOKENS   - Global max new tokens override

Usage:
    from mitre_expert.llm.local_llm import generate_answer

    answer = generate_answer(
        system_prompt="You are a helpful assistant.",
        user_content="Explain T1059 in simple terms.",
        max_new_tokens=512,
        temperature=0.3,
    )

    # Force a specific backend
    answer = generate_answer(..., backend="ollama")
    answer = generate_answer(..., backend="mlx")
    answer = generate_answer(..., backend="transformers")
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Import config values (with fallbacks if config not available)
# ---------------------------------------------------------------------------

try:
    from mitre_expert.config import (
        LOCAL_LLM_MODEL,
        LOCAL_LLM_BASE_URL,
        DEFAULT_DOCQA_TEMPERATURE,
        OLLAMA_BASE_URL,
    )
    _CONFIG_AVAILABLE = True
except ImportError:
    _CONFIG_AVAILABLE = False
    LOCAL_LLM_MODEL = "llama3.1:latest"
    LOCAL_LLM_BASE_URL = "http://127.0.0.1:11434"
    OLLAMA_BASE_URL = "http://127.0.0.1:11434"
    DEFAULT_DOCQA_TEMPERATURE = 0.3


# ---------------------------------------------------------------------------
# Backend Detection & Configuration
# ---------------------------------------------------------------------------

def _detect_best_backend() -> str:
    """
    Auto-detect the best available backend.
    Priority: Ollama (if server running) > MLX (if on Apple Silicon) > Transformers
    """
    # Check explicit override first
    env_backend = os.getenv("MITRE_LLM_BACKEND", "").strip().lower()
    if env_backend in ("ollama", "mlx", "transformers", "hf", "torch"):
        if env_backend in ("hf", "torch"):
            return "transformers"
        return env_backend

    # Default to Ollama (most common setup)
    return "ollama"


# Environment configuration
LLM_BACKEND = _detect_best_backend()

# ---------------------------------------------------------------------------
# Ollama Configuration
# ---------------------------------------------------------------------------

OLLAMA_MODEL = os.getenv("MITRE_OLLAMA_MODEL", LOCAL_LLM_MODEL)
OLLAMA_API_URL = os.getenv("MITRE_OLLAMA_BASE_URL", OLLAMA_BASE_URL)

# ---------------------------------------------------------------------------
# Model Paths Configuration (for MLX/Transformers)
# ---------------------------------------------------------------------------

# Default paths
DEFAULT_MLX_MODEL_PATH = Path.home() / "models_mlx" / "llama3.3-70b-4bit"
DEFAULT_HF_MODEL_PATH = (
    Path(__file__).resolve().parents[1] / "models" / "llama3.1-8b-instruct"
)

# Allow specific paths per backend, or a shared MITRE_DOCQA_MODEL_PATH for backward compat
MLX_MODEL_PATH = os.getenv(
    "MITRE_MLX_MODEL_PATH",
    os.getenv("MITRE_DOCQA_MODEL_PATH", str(DEFAULT_MLX_MODEL_PATH))
)
HF_MODEL_PATH = os.getenv(
    "MITRE_HF_MODEL_PATH",
    os.getenv("MITRE_DOCQA_MODEL_PATH", str(DEFAULT_HF_MODEL_PATH))
)

# Global limits
ENV_MAX_CONTEXT = os.getenv("MITRE_LLM_MAX_CONTEXT")
ENV_MAX_NEW_TOKENS = os.getenv("MITRE_LLM_MAX_NEW_TOKENS")


# ---------------------------------------------------------------------------
# Abstract Base Class for LLM Backends
# ---------------------------------------------------------------------------

class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    def __init__(self) -> None:
        self._loaded = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Return backend name for logging."""
        pass

    @abstractmethod
    def load(self) -> None:
        """Load the model and tokenizer."""
        pass

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_content: str,
        max_new_tokens: int = 512,
        temperature: Optional[float] = None,
        top_p: float = 0.9,
        repetition_penalty: float = 1.05,
    ) -> str:
        """Generate a response."""
        pass

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def _build_chat_messages(
        self, system_prompt: str, user_content: str
    ) -> List[Dict[str, str]]:
        """Build standard chat messages format."""
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

    def _apply_max_tokens_override(self, max_new_tokens: int) -> int:
        """Apply environment override for max_new_tokens."""
        if ENV_MAX_NEW_TOKENS is not None:
            try:
                env_max = int(ENV_MAX_NEW_TOKENS)
                if env_max > 0:
                    return min(max_new_tokens, env_max)
            except ValueError:
                pass
        return max_new_tokens


# ---------------------------------------------------------------------------
# Ollama Backend (HTTP API)
# ---------------------------------------------------------------------------

class OllamaBackend(LLMBackend):
    """
    Ollama-based inference backend via HTTP API.
    
    This is the easiest setup - just requires Ollama running with a model pulled.
    Uses the /api/chat endpoint for chat-style interactions.
    
    Tested with:
      - llama3.1:latest (8B)
      - llama3.2:latest
      - Any model available via `ollama list`
    """

    def __init__(self, model_name: str, base_url: str) -> None:
        super().__init__()
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self._api_url = f"{self.base_url}/api/chat"

    @property
    def name(self) -> str:
        return "Ollama"

    def load(self) -> None:
        """Verify Ollama server is accessible and model is available."""
        if self._loaded:
            return

        print(f"[local_llm:{self.name}] Checking Ollama server at: {self.base_url}")
        print(f"[local_llm:{self.name}] Model: {self.model_name}")

        # Check if server is running
        try:
            tags_url = f"{self.base_url}/api/tags"
            req = urllib.request.Request(tags_url, method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                
                # Check if our model is available
                model_base = self.model_name.split(":")[0]
                available = any(model_base in m for m in models)
                
                if not available:
                    print(f"[local_llm:{self.name}] WARNING: Model '{self.model_name}' not found.")
                    print(f"[local_llm:{self.name}] Available models: {models}")
                    print(f"[local_llm:{self.name}] Run: ollama pull {self.model_name}")
                else:
                    print(f"[local_llm:{self.name}] Model '{self.model_name}' is available")
                    
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot connect to Ollama server at {self.base_url}. "
                f"Make sure Ollama is running: ollama serve\n"
                f"Error: {e}"
            ) from e

        self._loaded = True
        print(f"[local_llm:{self.name}] Backend ready")

    def generate(
        self,
        system_prompt: str,
        user_content: str,
        max_new_tokens: int = 512,
        temperature: Optional[float] = None,
        top_p: float = 0.9,
        repetition_penalty: float = 1.05,
    ) -> str:
        if not self._loaded:
            self.load()

        max_new_tokens = self._apply_max_tokens_override(max_new_tokens)

        # Build chat messages
        messages = self._build_chat_messages(system_prompt, user_content)

        # Build request payload
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_new_tokens,
                "top_p": top_p,
                "repeat_penalty": repetition_penalty,
            }
        }

        # Temperature: None means greedy (temperature=0)
        if temperature is None:
            payload["options"]["temperature"] = 0.0
        else:
            payload["options"]["temperature"] = max(0.0, float(temperature))

        print(f"[local_llm:{self.name}] Generating with {self.model_name}...")
        print(f"[local_llm:{self.name}] System prompt length: {len(system_prompt)} chars")
        print(f"[local_llm:{self.name}] User content length: {len(user_content)} chars")

        # Make request
        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._api_url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Ollama API request failed: {e}\n"
                f"Make sure Ollama is running and the model is loaded."
            ) from e
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON response from Ollama: {e}") from e

        # Extract response text
        message = result.get("message", {})
        content = message.get("content", "")

        # Log some stats if available
        if "eval_count" in result:
            tokens = result.get("eval_count", 0)
            duration_ns = result.get("eval_duration", 1)
            tokens_per_sec = tokens / (duration_ns / 1e9) if duration_ns > 0 else 0
            print(f"[local_llm:{self.name}] Generated {tokens} tokens @ {tokens_per_sec:.1f} tok/s")

        return content.strip()


# ---------------------------------------------------------------------------
# MLX Backend (Apple Silicon Optimized)
# ---------------------------------------------------------------------------

class MLXBackend(LLMBackend):
    """
    MLX-based inference backend for Apple Silicon.
    
    Uses mlx-lm for efficient quantized model inference.
    Recommended for M1/M2/M3/M4 Macs with unified memory.
    
    Tested with:
      - LLaMA 3.3 70B 4-bit quantized (~37GB)
      - ~17 tokens/sec on Mac Studio
    
    NOTE: mlx-lm >= 0.30 uses sampler/logits_processors instead of direct
    temperature/top_p parameters. We use make_sampler() and make_logits_processors().
    """

    def __init__(self, model_path: str) -> None:
        super().__init__()
        self.model_path = model_path
        self._model: Any = None
        self._tokenizer: Any = None

    @property
    def name(self) -> str:
        return "MLX"

    def load(self) -> None:
        if self._loaded:
            return

        try:
            from mlx_lm import load as mlx_load
        except ImportError as e:
            raise ImportError(
                "MLX backend requires mlx-lm. Install with: pip install mlx-lm"
            ) from e

        print(f"[local_llm:{self.name}] Loading model from: {self.model_path}")

        self._model, self._tokenizer = mlx_load(self.model_path)
        self._loaded = True

        print(f"[local_llm:{self.name}] Model loaded successfully")

    def generate(
        self,
        system_prompt: str,
        user_content: str,
        max_new_tokens: int = 512,
        temperature: Optional[float] = None,
        top_p: float = 0.9,
        repetition_penalty: float = 1.05,
    ) -> str:
        if not self._loaded:
            self.load()

        from mlx_lm import generate as mlx_generate
        from mlx_lm.sample_utils import make_sampler

        # Import logits processors if available (for repetition penalty)
        try:
            from mlx_lm.sample_utils import make_logits_processors
            has_logits_processors = True
        except ImportError:
            has_logits_processors = False

        max_new_tokens = self._apply_max_tokens_override(max_new_tokens)

        # Build prompt using chat template
        messages = self._build_chat_messages(system_prompt, user_content)

        if hasattr(self._tokenizer, "apply_chat_template"):
            prompt_text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        else:
            # Fallback for LLaMA 3 style
            prompt_text = self._build_llama3_prompt(system_prompt, user_content)

        print(f"[local_llm:{self.name}] Prompt length (chars): {len(prompt_text)}")

        # MLX-LM 0.30+ API: use make_sampler instead of direct temperature parameter
        # temperature=0.0 means greedy decoding
        temp_value = 0.0 if temperature is None else max(0.0, float(temperature))
        
        # Create sampler with temperature, top_p, min_p, min_tokens_to_keep
        # make_sampler(temp, top_p, min_p=0.0, min_tokens_to_keep=1)
        sampler = make_sampler(temp_value, top_p, 0.0, 1)

        # Build generate kwargs
        gen_kwargs: Dict[str, Any] = {
            "prompt": prompt_text,
            "max_tokens": max_new_tokens,
            "sampler": sampler,
            "verbose": False,
        }

        # Add logits processors for repetition penalty if available
        if has_logits_processors and repetition_penalty != 1.0:
            # make_logits_processors(logit_bias, repetition_penalty, repetition_context_size)
            logits_processors = make_logits_processors(None, repetition_penalty, 20)
            gen_kwargs["logits_processors"] = logits_processors

        response = mlx_generate(
            self._model,
            self._tokenizer,
            **gen_kwargs,
        )

        return response.strip()

    def _build_llama3_prompt(self, system_prompt: str, user_content: str) -> str:
        """Fallback LLaMA 3 prompt format if chat template unavailable."""
        return (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{system_prompt}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n"
            f"{user_content}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
        )


# ---------------------------------------------------------------------------
# Transformers Backend (PyTorch - CUDA/CPU/MPS)
# ---------------------------------------------------------------------------

class TransformersBackend(LLMBackend):
    """
    Transformers/PyTorch-based inference backend.
    
    Supports CUDA, CPU, and MPS (Apple Silicon fallback).
    Uses HuggingFace transformers with automatic device selection.
    """

    def __init__(self, model_path: str) -> None:
        super().__init__()
        self.model_path = model_path
        self._model: Any = None
        self._tokenizer: Any = None
        self._device: Any = None
        self._dtype: Any = None

    @property
    def name(self) -> str:
        return "Transformers"

    def load(self) -> None:
        if self._loaded:
            return

        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError(
                "Transformers backend requires torch and transformers. "
                "Install with: pip install torch transformers"
            ) from e

        # Device / dtype selection
        if torch.backends.mps.is_available():
            self._device = torch.device("mps")
            self._dtype = torch.float32  # fp32 more stable on MPS for long prompts
        elif torch.cuda.is_available():
            self._device = torch.device("cuda")
            self._dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
        else:
            self._device = torch.device("cpu")
            self._dtype = torch.float32

        print(f"[local_llm:{self.name}] Loading model from: {self.model_path}")
        print(f"[local_llm:{self.name}] Device: {self._device}, dtype: {self._dtype}")

        self._tokenizer = AutoTokenizer.from_pretrained(
            self.model_path,
            local_files_only=True,
        )

        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

        self._model = AutoModelForCausalLM.from_pretrained(
            self.model_path,
            local_files_only=True,
            torch_dtype=self._dtype,
        )

        self._model.to(self._device)
        self._model.eval()

        self._loaded = True

        has_template = hasattr(self._tokenizer, "apply_chat_template")
        print(f"[local_llm:{self.name}] Chat template available: {has_template}")

    def _resolve_max_context(self) -> int:
        """Determine max context length from model config or env."""
        if ENV_MAX_CONTEXT is not None:
            try:
                val = int(ENV_MAX_CONTEXT)
                if val > 0:
                    return val
            except ValueError:
                pass

        cfg = self._model.config
        if hasattr(cfg, "max_position_embeddings") and cfg.max_position_embeddings:
            return int(cfg.max_position_embeddings)

        return 8192  # Safe default

    def generate(
        self,
        system_prompt: str,
        user_content: str,
        max_new_tokens: int = 512,
        temperature: Optional[float] = None,
        top_p: float = 0.9,
        repetition_penalty: float = 1.05,
    ) -> str:
        if not self._loaded:
            self.load()

        import torch

        max_new_tokens = self._apply_max_tokens_override(max_new_tokens)

        # Build prompt
        messages = self._build_chat_messages(system_prompt, user_content)

        if hasattr(self._tokenizer, "apply_chat_template"):
            prompt_text = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
            use_chat_template = True
        else:
            prompt_text = (
                f"[SYSTEM]\n{system_prompt}\n\n"
                f"[USER]\n{user_content}\n\n"
                f"[ASSISTANT]\n"
            )
            use_chat_template = False

        print(f"[local_llm:{self.name}] Using chat template: {use_chat_template}")
        print(f"[local_llm:{self.name}] Prompt length (chars): {len(prompt_text)}")

        # Tokenize
        inputs = self._tokenizer(
            prompt_text,
            return_tensors="pt",
            truncation=False,
        )

        input_ids = inputs["input_ids"].to(self._device)
        attention_mask = inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to(self._device)

        # Context window safety: truncate from left if too long
        max_context = self._resolve_max_context()
        max_input_tokens = max_context - max_new_tokens

        if input_ids.shape[1] > max_input_tokens:
            cut_from = input_ids.shape[1] - max_input_tokens
            input_ids = input_ids[:, cut_from:]
            if attention_mask is not None:
                attention_mask = attention_mask[:, cut_from:]
            print(
                f"[local_llm:{self.name}] Truncated to {max_input_tokens} tokens "
                f"(max_context={max_context})"
            )

        # Build generation kwargs
        gen_kwargs: Dict[str, Any] = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "max_new_tokens": max_new_tokens,
            "pad_token_id": self._tokenizer.pad_token_id,
            "eos_token_id": self._tokenizer.eos_token_id,
        }

        if temperature is None:
            # Greedy decoding
            gen_kwargs["do_sample"] = False
        else:
            # Sampling
            gen_kwargs.update({
                "do_sample": True,
                "temperature": max(0.1, float(temperature)),
                "top_p": float(top_p),
                "repetition_penalty": float(repetition_penalty),
            })

        # Generate
        with torch.inference_mode():
            output_ids = self._model.generate(**gen_kwargs)

        # Decode only new tokens
        generated = output_ids[0, input_ids.shape[-1]:]
        text = self._tokenizer.decode(generated, skip_special_tokens=True)

        return text.strip()


# ---------------------------------------------------------------------------
# Backend Factory & Singleton Management
# ---------------------------------------------------------------------------

_ACTIVE_BACKEND: Optional[LLMBackend] = None
_ACTIVE_BACKEND_TYPE: Optional[str] = None


def _get_backend(backend_type: Optional[str] = None) -> LLMBackend:
    """
    Get or create the appropriate backend instance.
    
    Args:
        backend_type: "ollama", "mlx", or "transformers". If None, uses auto-detected default.
    
    Returns:
        LLMBackend instance (lazily loaded)
    """
    global _ACTIVE_BACKEND, _ACTIVE_BACKEND_TYPE

    # Determine which backend to use
    requested = (backend_type or LLM_BACKEND).strip().lower()
    if requested in ("hf", "torch"):
        requested = "transformers"

    # Return existing backend if it matches
    if _ACTIVE_BACKEND is not None and _ACTIVE_BACKEND_TYPE == requested:
        return _ACTIVE_BACKEND

    # Create new backend
    if requested == "ollama":
        _ACTIVE_BACKEND = OllamaBackend(OLLAMA_MODEL, OLLAMA_API_URL)
        _ACTIVE_BACKEND_TYPE = "ollama"
    elif requested == "mlx":
        _ACTIVE_BACKEND = MLXBackend(MLX_MODEL_PATH)
        _ACTIVE_BACKEND_TYPE = "mlx"
    elif requested == "transformers":
        _ACTIVE_BACKEND = TransformersBackend(HF_MODEL_PATH)
        _ACTIVE_BACKEND_TYPE = "transformers"
    else:
        raise ValueError(
            f"Unknown LLM backend: {requested}. "
            f"Valid options: 'ollama', 'mlx', 'transformers'"
        )

    print(f"[local_llm] Using backend: {_ACTIVE_BACKEND_TYPE}")
    return _ACTIVE_BACKEND


def switch_backend(backend_type: str) -> None:
    """
    Explicitly switch to a different backend.
    
    This will unload the current backend and load the new one on next generation.
    
    Args:
        backend_type: "ollama", "mlx", or "transformers"
    """
    global _ACTIVE_BACKEND, _ACTIVE_BACKEND_TYPE

    requested = backend_type.strip().lower()
    if requested in ("hf", "torch"):
        requested = "transformers"

    if requested not in ("ollama", "mlx", "transformers"):
        raise ValueError(f"Unknown backend: {requested}")

    # Clear current backend
    _ACTIVE_BACKEND = None
    _ACTIVE_BACKEND_TYPE = None

    # Pre-fetch new backend (lazy load happens on first generate)
    print(f"[local_llm] Switching to backend: {requested}")


def get_current_backend_info() -> Dict[str, Any]:
    """
    Get information about the current backend configuration.
    
    Returns:
        Dict with backend type, model path, and load status.
    """
    return {
        "detected_backend": LLM_BACKEND,
        "active_backend": _ACTIVE_BACKEND_TYPE,
        "ollama_model": OLLAMA_MODEL,
        "ollama_url": OLLAMA_API_URL,
        "mlx_model_path": MLX_MODEL_PATH,
        "hf_model_path": HF_MODEL_PATH,
        "is_loaded": _ACTIVE_BACKEND.is_loaded if _ACTIVE_BACKEND else False,
        "config_available": _CONFIG_AVAILABLE,
    }


# ---------------------------------------------------------------------------
# Public API (Backward Compatible)
# ---------------------------------------------------------------------------

def generate_answer(
    system_prompt: str,
    user_content: str,
    max_new_tokens: int = 512,
    temperature: Optional[float] = None,
    top_p: float = 0.9,
    repetition_penalty: float = 1.05,
    backend: Optional[str] = None,
) -> str:
    """
    Generate an answer using the local LLM.
    
    This is the main public API. It automatically selects the best backend
    (Ollama by default, MLX on Apple Silicon if configured, Transformers otherwise)
    unless explicitly specified.
    
    Args:
        system_prompt: System message setting the assistant's behavior
        user_content: User's question or input
        max_new_tokens: Maximum tokens to generate (default: 512)
        temperature: Sampling temperature. None = greedy/deterministic (default: None)
        top_p: Nucleus sampling parameter (default: 0.9)
        repetition_penalty: Penalty for repeating tokens (default: 1.05)
        backend: Force specific backend ("ollama", "mlx", or "transformers"). None = auto-detect
    
    Returns:
        Generated text response
    
    Examples:
        # Basic usage (uses Ollama by default)
        >>> answer = generate_answer(
        ...     system_prompt="You are a cybersecurity expert.",
        ...     user_content="Explain T1059.001 PowerShell execution.",
        ... )
        
        # Force Ollama backend explicitly
        >>> answer = generate_answer(
        ...     system_prompt="You are a cybersecurity expert.",
        ...     user_content="Explain T1059.001 PowerShell execution.",
        ...     backend="ollama",
        ... )
        
        # With sampling
        >>> answer = generate_answer(
        ...     system_prompt="You are a cybersecurity expert.",
        ...     user_content="Explain T1059.001 PowerShell execution.",
        ...     temperature=0.3,
        ...     max_new_tokens=768,
        ... )
    """
    llm_backend = _get_backend(backend)

    return llm_backend.generate(
        system_prompt=system_prompt,
        user_content=user_content,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        top_p=top_p,
        repetition_penalty=repetition_penalty,
    )


# ---------------------------------------------------------------------------
# CLI for Testing
# ---------------------------------------------------------------------------

def _cli_test() -> None:
    """Simple CLI test for the local LLM."""
    import argparse

    parser = argparse.ArgumentParser(description="Test local LLM inference")
    parser.add_argument(
        "--backend",
        choices=["ollama", "mlx", "transformers", "auto"],
        default="auto",
        help="Backend to use (default: auto-detect, prefers ollama)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override Ollama model name (e.g., llama3.1:latest)",
    )
    parser.add_argument(
        "--prompt",
        default="Explain MITRE ATT&CK technique T1059 in simple terms.",
        help="User prompt to send",
    )
    parser.add_argument(
        "--system",
        default="You are a helpful cybersecurity expert specializing in MITRE ATT&CK.",
        help="System prompt",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=256,
        help="Maximum tokens to generate",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="Sampling temperature (None for greedy)",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Print backend configuration info and exit",
    )

    args = parser.parse_args()

    # Override model if specified
    global OLLAMA_MODEL
    if args.model:
        OLLAMA_MODEL = args.model

    if args.info:
        print("=" * 60)
        print("Local LLM Configuration")
        print("=" * 60)
        info = get_current_backend_info()
        for key, value in info.items():
            print(f"  {key}: {value}")
        print("=" * 60)
        return

    backend = None if args.backend == "auto" else args.backend

    print("=" * 60)
    print(f"Testing Local LLM (backend={backend or 'auto'})")
    print("=" * 60)
    print(f"System: {args.system[:80]}...")
    print(f"Prompt: {args.prompt}")
    print("-" * 60)

    response = generate_answer(
        system_prompt=args.system,
        user_content=args.prompt,
        max_new_tokens=args.max_tokens,
        temperature=args.temperature,
        backend=backend,
    )

    print(f"\nResponse:\n{response}")
    print("=" * 60)


if __name__ == "__main__":
    _cli_test()