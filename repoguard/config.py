"""
RepoGuard Configuration
Automatically detects paths based on installation location
"""
import os
from pathlib import Path

# Detect installation directory (parent of repoguard package)
INSTALL_DIR = Path(__file__).parent.parent.resolve()

# Paths relative to installation directory
MODELS_HUB_DIR = INSTALL_DIR / "models_hub"
DATA_DIR = INSTALL_DIR / "data"
RULES_DIR = INSTALL_DIR / "rules"

def get_install_dir() -> Path:
    """Get the installation directory."""
    return INSTALL_DIR

def get_models_dir() -> Path:
    """Get models directory."""
    return MODELS_HUB_DIR

def get_rules_dir() -> Path:
    """Get rules directory."""
    return RULES_DIR

def get_data_dir() -> Path:
    """Get data directory."""
    return DATA_DIR

def resolve_path(relative_path: str) -> Path:
    """Resolve a path relative to installation directory."""
    return INSTALL_DIR / relative_path

if __name__ == "__main__":
    print(f"Installation directory: {INSTALL_DIR}")
    print(f"Models directory: {MODELS_HUB_DIR}")
    print(f"Rules directory: {RULES_DIR}")
    print(f"Data directory: {DATA_DIR}")