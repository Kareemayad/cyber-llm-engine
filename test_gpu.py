import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

print("MPS available:", torch.backends.mps.is_available())

model_path = "src/mitre_expert/models/llama3.1-8b-instruct"
tok = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
model = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True)

print("Before .to:", next(model.parameters()).device)
model.to("mps")
print("After .to:", next(model.parameters()).device)
