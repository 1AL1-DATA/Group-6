"""
Download and cache models for offline use
Run this to bundle models locally
"""
from repoguard.config import get_models_dir

MODELS_TO_DOWNLOAD = [
    ("microsoft/graphcodebert-base", "graphcodebert"),
    ("sentence-transformers/all-MiniLM-L6-v2", "minilm-l6-v2"),
]

def download_model(huggingface_name: str, local_name: str) -> bool:
    """Download and cache a model."""
    from transformers import AutoModel, AutoTokenizer
    
    target_dir = get_models_dir() / local_name
    if target_dir.exists():
        print(f"  {local_name} already exists, skipping")
        return True
    
    print(f"  Downloading {huggingface_name}...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(huggingface_name)
        tokenizer.save_pretrained(target_dir)
        
        model = AutoModel.from_pretrained(huggingface_name)
        model.save_pretrained(target_dir)
        
        print(f"  Saved to {target_dir}")
        return True
    except Exception as e:
        print(f"  Failed: {e}")
        return False

def download_all():
    """Download all models to local cache."""
    print("Downloading models to local cache...")
    get_models_dir().mkdir(parents=True, exist_ok=True)
    
    for hf_name, local_name in MODELS_TO_DOWNLOAD:
        print(f"Downloading {local_name}:")
        download_model(hf_name, local_name)
    
    print("\nDone! Models are now cached locally.")

if __name__ == "__main__":
    download_all()