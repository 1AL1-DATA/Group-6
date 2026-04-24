#!/usr/bin/env python3
"""RepoGuard CLI entry point."""
import sys
import os
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repoguard import RepoGuard
from repoguard.engine.aggregator import Reporter


def check_ollama(api_base: str = "http://localhost:11434") -> dict:
    """Check if Ollama is available and return model info."""
    try:
        import requests
        r = requests.get(f"{api_base}/api/tags", timeout=2)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def test_llm(api_base: str, model: str) -> bool:
    """Test LLM connection."""
    try:
        import requests
        payload = {"model": model, "messages": [{"role": "user", "content": "test"}], "stream": False}
        r = requests.post(f"{api_base}/api/chat", json=payload, timeout=30)
        return r.status_code == 200
    except Exception as e:
        return False


def interactive_model_select(api_base: str, default_model: str = None) -> str:
    """Interactive model selection from Ollama."""
    ollama_info = check_ollama(api_base)
    if not ollama_info:
        return None
    
    models = ollama_info.get("models", [])
    if not models:
        return None
    
    print("\n━━━ Available Models ━━━")
    for i, m in enumerate(models):
        name = m.get("name", m.get("model", "unknown"))
        size_gb = m.get("size", 0) / 1e9
        details = m.get("details", {})
        params = details.get("parameter_size", "?")
        marker = " ←default" if name == default_model or (default_model is None and i == 0) else ""
        print(f"  {i+1}. {name} ({params}, {size_gb:.1f}GB){marker}")
    
    if default_model:
        return default_model
    
    print("  0. Cancel")
    choice = input("\nSelect model [1]: ").strip()
    
    if not choice or choice == "1":
        return models[0].get("name") or models[0].get("model")
    elif choice.isdigit() and 0 < int(choice) <= len(models):
        return models[int(choice)-1].get("name") or models[int(choice)-1].get("model")
    elif choice == "0":
        return None
    
    return choice


def run_scan(args: argparse.Namespace) -> int:
    """Execute scan command."""
    # Check LLM availability
    use_llm = args.llm
    llm_model = args.model
    
    if use_llm:
        ollama_info = check_ollama(args.api)
        if not ollama_info:
            print("⚠ Ollama not running. Install from: https://ollama.ai")
            print("  Falling back to rule-based scan...")
            use_llm = False
        else:
            models = ollama_info.get("models", [])
            if not models:
                print("⚠ No models found. Falling back...")
                use_llm = False
            elif not llm_model:
                llm_model = interactive_model_select(args.api)
                if llm_model and test_llm(args.api, llm_model):
                    print(f"✓ Connected to {llm_model}")
                else:
                    print("⚠ Could not connect to model. Falling back...")
                    use_llm = False
    
    # Initialize scanner
    guard = RepoGuard(
        use_llm=use_llm,
        llm_model=llm_model,
        llm_api_base=args.api,
        export_prompts=args.export_prompts
    )
    
    if args.export_prompts:
        print(f"📤 Prompts → {args.export_prompts}/")
    
    reporter = Reporter()
    
    # Execute scan
    path = args.path or "."
    
    if not os.path.exists(path):
        print(f"✗ Path not found: {path}")
        return 1
    
    is_file = os.path.isfile(path)
    print(f"{'📄' if is_file else '📁'} Scanning: {path}")
    
    if is_file:
        report = guard.scan_file(path)
    else:
        report = guard.scan_repository(path)
    
    reporter.print_report(report)
    
    if use_llm and llm_model:
        print(f"\n🔗 LLM: {llm_model}")
    
    if args.json:
        print("\n--- JSON ---")
        print(json.dumps(report, indent=2))
    
    # Exit codes
    summary = report.get("summary", {})
    if summary.get("critical_count", 0) > 0:
        return 2
    elif summary.get("high_count", 0) > 0:
        return 1
    return 0


def run_code(args: argparse.Namespace) -> int:
    """Execute code scan command."""
    code = args.code
    
    guard = RepoGuard(
        use_llm=args.llm,
        llm_model=args.model,
        llm_api_base=args.api
    )
    
    report = guard.scan_code(code, "input.py")
    reporter = Reporter()
    reporter.print_report(report)
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="RepoGuard - AI-powered security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  repoguard scan .                          Scan current directory
  repoguard scan ./src --llm                Scan with LLM analysis
  repoguard scan app.py --json               JSON output
  repoguard scan . --export-prompts out/    Export LLM prompts
  repoguard code 'eval(x)'                  Scan code string
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan file or directory")
    scan_parser.add_argument("path", nargs="?", help="File or directory to scan")
    scan_parser.add_argument("--llm", "-l", action="store_true", help="Enable LLM analysis")
    scan_parser.add_argument("--api", "-a", default="http://localhost:11434", help="Ollama API URL")
    scan_parser.add_argument("--model", "-m", help="Model name")
    scan_parser.add_argument("--export-prompts", "-e", help="Export prompts to directory")
    scan_parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    
    # Code command
    code_parser = subparsers.add_parser("code", help="Scan code string")
    code_parser.add_argument("code", help="Code to scan")
    code_parser.add_argument("--llm", "-l", action="store_true", help="Enable LLM analysis")
    code_parser.add_argument("--api", "-a", default="http://localhost:11434", help="Ollama API URL")
    code_parser.add_argument("--model", "-m", help="Model name")
    
    # Version
    parser.add_argument("--version", "-v", action="version", version="%(prog)s 1.0.0")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "code":
        sys.exit(run_code(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()