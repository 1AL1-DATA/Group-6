"""
Local Model Hub for RepoGuard
Stores embedded models for offline/stable usage
"""
from repoguard.config import get_models_dir
from typing import Dict, Optional, List
import os

LOCAL_MODELS = {
    "codebert-base": {
        "path": "codebert",
        "description": "Microsoft CodeBERT for code analysis",
        "source": "microsoft/graphcodebert-base"
    },
    "minilm-l6": {
        "path": "minilm-l6-v2",
        "description": "MiniLM-L6-v2 for semantic similarity",
        "source": "sentence-transformers/all-MiniLM-L6-v2"
    },
    "graphcodebert": {
        "path": "graphcodebert",
        "description": "GraphCodeBERT",
        "source": "microsoft/graphcodebert-base"
    }
}

def get_local_models() -> List[str]:
    """Get list of available local models."""
    return list(LOCAL_MODELS.keys())

def get_model_path(model_name: str) -> Optional[str]:
    """Get path to local model."""
    if model_name in LOCAL_MODELS:
        model_dir = get_models_dir() / LOCAL_MODELS[model_name]["path"]
        if model_dir.exists():
            return str(model_dir)
    return None

def is_model_local(model_name: str) -> bool:
    """Check if model is available locally."""
    return get_model_path(model_name) is not None

def list_local_models() -> Dict:
    """List all local models with details."""
    return {
        name: {
            "available": is_model_local(name),
            "description": info["description"],
            "source": info["source"]
        }
        for name, info in LOCAL_MODELS.items()
    }

if __name__ == "__main__":
    print("Local Models Available:")
    for name, info in LOCAL_MODELS.items():
        status = "✓" if is_model_local(name) else "✗"
        print(f"  {status} {name}: {info['description']}")