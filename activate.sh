#!/bin/bash
# Activate Group-6 conda environment and switch to project directory

CONDA_PATH="$HOME/miniconda3"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if conda is in PATH
if ! command -v conda &> /dev/null; then
    export PATH="$CONDA_PATH/bin:$PATH"
fi

# Activate environment
conda activate group6 2>/dev/null || source "$CONDA_PATH/bin/activate" group6

# Change to project directory
cd "$PROJECT_DIR"

echo "Activated: group6 environment"
echo "Project: $PROJECT_DIR"