#!/bin/bash
# Group-6 Conda Setup Script
# Run this to initialize or update the conda environment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONDA_PATH="/home/a/miniconda3"
ENV_FILE="$SCRIPT_DIR/environment.yml"

echo "=== Group-6 Conda Setup ==="

# Check for conda
if [ ! -d "$CONDA_PATH" ]; then
    echo "Installing Miniconda..."
    wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh
    bash /tmp/miniconda.sh -b -p "$CONDA_PATH"
    rm /tmp/miniconda.sh
    
    # Accept ToS
    "$CONDA_PATH/bin/conda" tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main 2>/dev/null || true
    "$CONDA_PATH/bin/conda" tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r 2>/dev/null || true
fi

export PATH="$CONDA_PATH/bin:$PATH"

# Create or update environment
echo "Creating/updating 'group6' environment..."
"$CONDA_PATH/bin/conda" env update -f "$ENV_FILE"

echo ""
echo "=== Setup Complete ==="
echo "To activate: conda activate group6"
echo "To run: python repoguard_cli.py scan ."