# RepoGuard - Project Continuity Summary

## Current State (April 2026)

### Project Location
```
/home/a/PycharmProjects/Group-6/
```

### What Works
- ✅ Multi-stage vulnerability scanning (rules + heuristic + risk scoring)
- ✅ CLI with LLM support (`--llm` flag)
- ✅ Jupyter notebook for testing
- ✅ RL Learner module for training on findings
- ✅ Auto path resolution (works from any folder)
- ✅ 12+ vulnerability types detected

### Quick Start
```bash
# Create and activate conda environment
cd /home/a/PycharmProjects/Group-6
conda env create -f environment.yml
conda activate group6

# Basic scan
python3.10 repoguard_cli.py scan /path/to/code.py

# With LLM
python3.10 repoguard_cli.py scan /path/to/code.py --llm
```

### Known Issues
- ⚠️ Large model files excluded (use Ollama for LLM)
- ⚠️ GPU memory needed for CodeBERT
- ⚠️ Variable name bug in `scan_code` - FIXED (`content` -> `code`)

### Architecture
```
repoguard/
├── __init__.py         # RepoGuard main class
├── config.py          # Path auto-resolution (important!)
├── learner.py          # RL Training loop
├── engine/
│   ├── rules_engine.py       # Deterministic rules
│   ├── heuristic_analyzer.py # Regex + semantic patterns
│   ├── context_analyzer.py  # False positive filter
│   └── aggregator.py        # Report generation
└── models/
    ├── risk_scorer.py       # CodeBERT/MiniLM scoring
    └── llm_analyzer.py   # Ollama integration
```

### Key Integration Points (for next developer)
1. **Config auto-detects paths**: `from repoguard.config import get_install_dir`
2. **LLM uses Ollama**: Default `http://localhost:11434`
3. **Learner saves data**: `data/training_data.json`
4. **CLI uses argparse**: Run with `--help` for options

### To Push to GitHub
```bash
cd /home/a/PycharmProjects/Group-6
git init (if not done)
git add .
git commit -m "RepoGuard: LLM security scanner"
git remote add origin https://github.com/HSLU-DLM03-DevOps-LLMs/Group-6.git
git push -u origin main
```

### Future Work (Priority Order)
1. [High] Add prompt injection guardrails
2. [High] FastAPI deployment
3. [Medium] Streamlit dashboard
4. [Medium] More training data for RL learner

### Test Files
- `/home/a/Desktop/vuln_app.py` - Flask with 19 vulns
- `test_notebook.ipynb` - Jupyter test notebook

---
*Last updated: April 2026*