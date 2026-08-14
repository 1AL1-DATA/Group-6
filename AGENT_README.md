# RepoGuard - Security Scanner for AI Agents

## Quick Start

```bash
# Create conda environment
cd Group-6
conda env create -f environment.yml
conda activate group6

# Run the scanner
python3.10 repoguard_cli.py scan <FILE_OR_DIR_PATH> --llm
```

## Options

| Flag | Description | Example |
|------|-------------|---------|
| `--llm` | Enable LLM analysis (interactive model selection) | `--llm` |
| `--model` | Specify model (optional) | `--model qwen3.5:9b` |
| `--api` | Custom API URL | `--api http://localhost:11434` |
| `--export-prompts` | Save prompts to file | `--export-prompts /tmp/prompts/` |

## Examples

### Scan a file (interactive model selection)
```bash
python3.10 repoguard_cli.py scan /path/to/code.py --llm
```

### Scan with specific model
```bash
python3.10 repoguard_cli.py scan /path/to/code.py --llm --model qwen3.5:9b
```

### Scan a directory
```bash
python3.10 repoguard_cli.py scan /path/to/project/ --llm
```

### Export prompts for external LLM
```bash
python3.10 repoguard_cli.py scan /path/to/code.py --llm --export-prompts /tmp/repoguard_prompts/
```

## Output Format

```
=== Security Report ===

1. [Critical] Secrets Leak
   File: app.py:42
   Evidence: API_KEY = 'sk-xxx'
   Explanation: ...
   Fix: ...

2. [High] SQL Injection
   File: app.py:123
   Evidence: query = f"SELECT * FROM users WHERE id = {user_id}"
```

## Exit Codes

- `0` - No critical/high issues
- `1` - High severity found
- `2` - Critical severity found

## For External Agents

To use RepoGuard in this project:

1. Activate conda environment: `conda activate group6`
2. Run: `cd Group-6 && python3.10 repoguard_cli.py scan <TARGET> --llm`
2. The tool will list available Ollama models and prompt for selection
3. Report findings with severity and explanation
4. For better analysis: use `--export-prompts <DIR>` then process with external LLM