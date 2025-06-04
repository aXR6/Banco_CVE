# embedder.py

from sentence_transformers import SentenceTransformer
import torch
from config import EMBEDDING_DEVICE

# Determina o dispositivo
if EMBEDDING_DEVICE == "cpu":
    _device = "cpu"
elif EMBEDDING_DEVICE == "gpu":
    _device = "cuda"
else:
    _device = "cuda" if torch.cuda.is_available() else "cpu"

# Inicializa o modelo apenas uma vez
_model = SentenceTransformer('all-mpnet-base-v2', device=_device)

def get_embedding(text: str) -> list[float]:
    """
    Recebe uma string (texto) e retorna uma lista de floats de tamanho 768,
    correspondente ao embedding gerado pelo modelo all-mpnet-base-v2.
    """
    if not text:
        # se texto vazio, retorna vetor de zeros
        return [0.0] * 768
    # Gera o vetor (shape: (768,))
    emb = _model.encode(text, show_progress_bar=False, convert_to_numpy=True)
    return emb.tolist()
