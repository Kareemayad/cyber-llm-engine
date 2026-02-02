import torch
from FlagEmbedding import BGEM3FlagModel, FlagReranker

print("MPS available:", torch.backends.mps.is_available())

emb = BGEM3FlagModel(
    "./models/bge-m3",
    use_fp16=True,
)

rerank = FlagReranker(
    "./models/bge-reranker-v2-m3",
    use_fp16=True,
)

# Embedding test
q = ["What is MITRE ATT&CK technique T1059?"]
docs = [
    "T1059 Command and Scripting Interpreter: adversaries abuse cmd, PowerShell, bash, etc.",
    "Cooking recipes for pasta and tomato sauce.",
]

q_vec = emb.encode(q, batch_size=1, max_length=512)["dense_vecs"]
d_vec = emb.encode(docs, batch_size=2, max_length=512)["dense_vecs"]

import numpy as np
sim = np.array(q_vec) @ np.array(d_vec).T
print("Dense similarity:", sim)

# Reranker test
pairs = [[q[0], docs[0]], [q[0], docs[1]]]
scores = rerank.compute_score(pairs, normalize=True)
print("Rerank scores:", scores)
