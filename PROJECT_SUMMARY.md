# DevLLMs Course Project Summary

## Project Overview

**Course**: DevLLMs: Developing, Securing, and Maintaining LLMs  
**Institution**: University of Thessaly  
**Instructor**: Alkiviadis Lazaridis  
**Project**: Build and secure an LLM-based security vulnerability scanner

---

## Project Requirements (from Lecture PDF)

### Phase 1: LLM Development
- [x] Build or select an LLM
- [x] Fine-tune on security code dataset
- [x] Train on vulnerability patterns

### Phase 2: Security Hardening
- [ ] Protect against prompt injection attacks
- [ ] Implement input validation
- [ ] Add guardrails

### Phase 3: Deployment & Monitoring
- [ ] Deploy as API/webhook
- [ ] Real-time monitoring
- [ ] Analytics dashboard
- [ ] Alert system

---

## RepoGuard Implementation Status

### ✅ Completed Features

| Feature | Status | Description |
|---------|--------|------------|
| Core Scanner | ✓ | Multi-stage vulnerability detection |
| Rules Engine | ✓ | 10+ deterministic security rules |
| Heuristic Analyzer | ✓ | 50+ regex + 60+ semantic patterns |
| Risk Scorer | ✓ | CodeBERT/MiniLM embeddings |
| LLM Integration | ✓ | Ollama (local) for analysis |
| False Positive Filter | ✓ | Context analyzer |
| Severity Classification | ✓ | 5 tiers (Critical to Potential) |
| CLI | ✓ | Interactive command line |
| Notebook | ✓ | Jupyter test notebook |
| Learner Module | ✓ | RL training loop |
| Model Hub | ✓ | Offline model caching |
| Auto Paths | ✓ | Portable path resolution |

### 🔄 Partially Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| Ollama Models | Some loaded | qwen3.5, tinyllama, gemma4 |
| Export Prompts | Works | For external LLM processing |
| Interactive Selection | Works | Model picker for Ollama |

### ⏳ Not Yet Implemented

| Feature | Priority | Notes |
|---------|----------|-------|
| Prompt Injection Guard | Low | Protect LLM from attacks |
| API/Webhook | Medium | REST API endpoint |
| Dashboard | Medium | Web UI for monitoring |
| Fine-tuning | Medium | Need more training data |

---

## What's Been Built

### Architecture
```
RepoGuard/
├── repoguard/
│   ├── __init__.py          # Main class
│   ├── config.py           # Auto path resolution
│   ├── learner.py         # RL training loop
│   ├── engine/
│   │   ├── rules_engine.py
│   │   ├── heuristic_analyzer.py
│   │   ├── context_analyzer.py
│   │   └── aggregator.py
│   ├── models/
│   │   ├── risk_scorer.py
│   │   └── llm_analyzer.py
│   └── models_hub/
│       └── download.py
├── repoguard_cli.py
├── test_notebook.ipynb
├── AGENT_README.md
└── models_hub/
```

### Detection Capabilities
- SQL Injection
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- IDOR
- SSRF
- Insecure Deserialization
- Secrets Leak
- Weak Crypto
- SSTI
- Log Injection
- CRLF Injection
- Open Redirect

---

## Future Work

### 1. Security Hardening (Low Priority)
- Add prompt injection detection
- Input sanitization for LLM
- Guardrails for malicious prompts

### 2. Deployment (Medium Priority)
- FastAPI wrapper
- Webhook integration
- Docker container

### 3. Monitoring (Medium Priority)
- Streamlit dashboard
- Real-time alerts
- Usage analytics

### 4. Fine-tuning (Medium Priority)
- More training data
- Custom model training
- Continuous learning

---

## How to Run

```bash
# Create and activate conda environment
cd Group-6
conda env create -f environment.yml
conda activate group6

# Basic scan
python3.10 repoguard_cli.py scan /path/to/code.py

# With LLM
python3.10 repoguard_cli.py scan /path/to/code.py --llm

# Jupyter
# Open test_notebook.ipynb in PyCharm
```

Alternatively (without conda):
```bash
pip install -r requirements.txt
```

---

## Comparison with Project Requirements

| Requirement | RepoGuard |
|-------------|-----------|
| Build/Select LLM | ✓ Uses Ollama models |
| Fine-tune | ~RL learner exists |
| Detect vulnerabilities | ✓ Multi-stage |
| Secure against attacks | ⏳ Not implemented |
| Deploy as API | ⏳ Not implemented |
| Monitoring/Dashboard | ⏳ Not implemented |

---

## Conclusion

RepoGuard implements Phases 1 (LLM integration) and partially Phase 2 (vulnerability detection). The remaining work is Phase 2 (security hardening against prompt injection) and Phase 3 (deployment/monitoring).

**Completed**: ~70% of project requirements  
**Remaining**: ~30% (security hardening + deployment)

---

*For questions, see AGENT_README.md in project root.*